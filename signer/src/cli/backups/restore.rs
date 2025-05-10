use std::path::{Path, PathBuf};

use prost::Message;
use secp256k1::{
    Message as SecpMessage,
    Secp256k1, // Use specific Hash type
    hashes::{Hash, sha256::Hash as Sha256Hash},
};

use crate::{
    cli::backups::BACKUP_FILE_VERSION,
    keys::{PrivateKey, PublicKey},
    proto::sbtc::signer::v1::backups::BackupFile,
    storage::{DbRead, DbWrite, model},
};

/// Errors which can occur during the restore process.
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    /// Failed to read the backup file from the filesystem.
    #[error("failed to read backup file '{0}': {1}.")]
    ReadFailed(PathBuf, #[source] std::io::Error),

    /// Failed to decode the backup file content using protobuf.
    #[error("failed to decode backup file '{0}': {1}.")]
    DecodeFailed(PathBuf, #[source] prost::DecodeError),

    /// The backup file format version does not match the expected version.
    #[error("backup file '{0}' has invalid format version {1}, expected {2}.")]
    InvalidFormatVersion(PathBuf, u32, u32),

    /// The backup file header is missing or contains invalid/incomplete data.
    #[error("backup file header is incomplete or invalid in '{0}'.")]
    InvalidHeader(PathBuf),

    /// Failed to prepare the message digest for signature verification.
    #[error("failed to prepare message for signature verification: {0}.")]
    SigningFailed(#[from] secp256k1::Error),

    /// The signature in the backup file header is invalid for the backup body content.
    #[error("signature verification failed for backup '{0}', data may be corrupt.")]
    SignatureVerificationFailed(PathBuf),

    /// The backup was signed by a different key than the current signer's key, and `force` was not used.
    #[error(
        "backup file '{0}' was signed by a different key ({1}) than the current signer key ({2}). Use --force to restore anyway."
    )]
    SignatureMismatchRequiresForce(PathBuf, PublicKey, PublicKey),

    /// An error occurred when reading existing data from the database during restore.
    #[error("database read error during restore: {0}")]
    DbRead(#[source] Box<crate::error::Error>),

    /// An error occurred when writing restored data to the database.
    #[error("failed to write data during restore from '{0}': {1}")]
    DbWrite(PathBuf, #[source] Box<crate::error::Error>),

    /// Failed to convert between internal model types and protobuf types.
    #[error("failed to convert data during restore from '{0}': {1}")]
    ProtoConvert(PathBuf, #[source] Box<crate::error::Error>),
}

/// Restores signer state from a backup file.
///
/// Reads the backup file, verifies its integrity (format version) and signature
/// against the public key stored in the header. If the signature is valid but
/// the public key in the backup header does not match the current `signer_private_key`,
/// it indicates a potential key rotation. In this scenario, the restore will only
/// proceed if `force` is true. Finally, it writes the contained data (DKG shares)
/// to the signer's storage, skipping shares that already exist.
///
/// # Arguments
/// * `storage` - A database context implementing `DbWrite` and `DbRead`.
/// * `signer_private_key` - The current private key of the signer, used for key comparison.
/// * `path` - The file system path to the backup file.
/// * `force` - If true, allows restoring a backup signed by a different key.
///
/// # Errors
/// Returns `RestoreError` if reading, decoding, validation, verification, or database
/// operations fail. Specifically returns `RestoreError::SignatureMismatchRequiresForce`
/// if keys mismatch and `force` is false.
#[allow(unused)]
pub async fn restore_backup<S, P>(
    storage: &S,
    signer_private_key: &PrivateKey,
    path: P,
    force: bool,
) -> Result<(), RestoreError>
where
    P: AsRef<Path>,
    S: DbWrite + DbRead,
{
    let path = path.as_ref();

    // Read backup file
    let backup_bytes = tokio::fs::read(path)
        .await
        .map_err(|e| RestoreError::ReadFailed(path.to_path_buf(), e))?;

    // Decode BackupFile message
    let decoded_backup = BackupFile::decode(backup_bytes.as_slice())
        .map_err(|e| RestoreError::DecodeFailed(path.to_path_buf(), e))?;

    // Validate header
    let header = decoded_backup
        .header
        .ok_or_else(|| RestoreError::InvalidHeader(path.to_path_buf()))?;

    if header.format_version != BACKUP_FILE_VERSION {
        return Err(RestoreError::InvalidFormatVersion(
            path.to_path_buf(),
            header.format_version,
            BACKUP_FILE_VERSION,
        ));
    }

    let backup_public_key_proto = header
        .public_key
        .ok_or_else(|| RestoreError::InvalidHeader(path.to_path_buf()))?;
    let signature_proto = header
        .signature
        .ok_or_else(|| RestoreError::InvalidHeader(path.to_path_buf()))?;

    // Convert proto key and signature to internal types
    let backup_public_key: PublicKey = backup_public_key_proto
        .try_into()
        .map_err(|e| RestoreError::ProtoConvert(path.to_path_buf(), Box::new(e)))?;
    let signature: secp256k1::ecdsa::Signature = signature_proto
        .try_into()
        .map_err(|e| RestoreError::ProtoConvert(path.to_path_buf(), Box::new(e)))?;

    // Get current public key for comparison
    let current_public_key = PublicKey::from_private_key(signer_private_key);

    // Verify signature
    let body = decoded_backup
        .body
        .ok_or_else(|| RestoreError::InvalidHeader(path.to_path_buf()))?;

    let body_bytes_for_verify = body.encode_to_vec();
    let body_hash = Sha256Hash::hash(&body_bytes_for_verify);
    let msg =
        SecpMessage::from_digest_slice(&body_hash[..]).map_err(RestoreError::SigningFailed)?;

    let secp = Secp256k1::verification_only();
    match secp.verify_ecdsa(&msg, &signature, &backup_public_key) {
        Ok(_) => {
            // Signature is valid according to the key in the backup file.
            // Now, check if that key matches the current signer's key.
            if backup_public_key != current_public_key {
                if !force {
                    // Keys differ and force is not set, return error.
                    return Err(RestoreError::SignatureMismatchRequiresForce(
                        path.to_path_buf(),
                        backup_public_key,
                        current_public_key,
                    ));
                } else {
                    // Keys differ, but force is set, proceed with warning.
                    println!(
                        "NOTE: --force flag provided, proceeding with restore despite key mismatch."
                    );
                }
            }
            // Keys match, or keys differ but force=true. Proceed to restore.
        }
        Err(e) => {
            // Signature is invalid according to the key in the backup file.
            // This implies corruption or a bug, regardless of the current key or force flag.
            return Err(RestoreError::SignatureVerificationFailed(
                path.to_path_buf(),
            ));
        }
    }

    // Restore data (write to database)
    for proto_share in body.dkg_shares {
        // Convert proto share back to model share
        let model_share: model::EncryptedDkgShares = proto_share
            .try_into()
            .map_err(|e| RestoreError::ProtoConvert(path.to_path_buf(), Box::new(e)))?;

        let existing = storage
            .get_encrypted_dkg_shares(&model_share.aggregate_key)
            .await
            .map_err(|e| RestoreError::DbRead(Box::new(e)))?;

        // Don't attempt to import if the share already exists
        if let Some(shares) = existing {
            println!(
                "NOTE: Skipping import of existing shares for aggregate key '{}'",
                shares.aggregate_key
            );
            continue;
        }

        // Write the non-existing shares to the db
        println!(
            "Importaing shares for aggregate key '{}'",
            model_share.aggregate_key
        );
        storage
            .write_encrypted_dkg_shares(&model_share)
            .await
            .map_err(|e| RestoreError::DbWrite(path.to_path_buf(), Box::new(e)))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    use assert_matches::assert_matches;
    use fake::{Fake, Faker};
    use tempfile::tempdir;

    use crate::{
        cli::backups::backup_signer,
        keys::PrivateKey,
        storage::{DbRead, in_memory::Store},
        testing::get_rng,
    };

    // Helper to create a valid backup file for testing restore
    async fn create_test_backup_file(
        backup_path: &Path,
        signer_private_key: &PrivateKey,
        shares: Vec<model::EncryptedDkgShares>,
    ) {
        let store = Store::new_shared();
        for share in &shares {
            store.write_encrypted_dkg_shares(share).await.unwrap();
        }

        // Execute the backup
        backup_signer(&store, signer_private_key, backup_path)
            .await
            .expect("failed to create backup file");
    }

    // Helper to get all shares from store (for verification)
    async fn get_all_shares_from_store(
        store: &impl DbRead,
    ) -> Result<Vec<model::EncryptedDkgShares>, crate::error::Error> {
        store.get_all_encrypted_dkg_shares().await
    }

    /// Tests successful restore when the backup key matches the current signer key.
    ///
    /// Verifies that only the 'Verified' shares from the backup are correctly
    /// written to an initially empty store.
    #[tokio::test]
    async fn restore_success_matching_key() {
        let mut rng = get_rng();
        let temp_dir = tempdir().unwrap();
        let backup_path = temp_dir.path().join("restore_success.bin");

        // New signer key
        let signer_key = PrivateKey::new(&mut rng);

        // Create some DKG shares, mostly randomized except 1 which will be verified
        let original_shares: Vec<model::EncryptedDkgShares> = vec![
            Faker.fake_with_rng(&mut rng),
            Faker.fake_with_rng(&mut rng),
            Faker.fake_with_rng(&mut rng),
            Faker.fake_with_rng(&mut rng),
            // Ensure we always have at least one verified that will be included
            model::EncryptedDkgShares {
                dkg_shares_status: model::DkgSharesStatus::Verified,
                ..Faker.fake_with_rng(&mut rng)
            },
        ];

        // Filter out the verified shares for comparison (only verified are included in the backup)
        let expected_shares = original_shares
            .iter()
            .filter(|s| s.dkg_shares_status == model::DkgSharesStatus::Verified)
            .cloned()
            .collect::<Vec<_>>();

        // Create the backup file using the signer key
        create_test_backup_file(&backup_path, &signer_key, original_shares.clone()).await;

        // Setup restore context with the SAME key and an EMPTY store
        let restore_store = Store::new_shared();

        // Perform restore (force = false)
        restore_backup(&restore_store, &signer_key, &backup_path, false)
            .await
            .expect("failed to restore backup");

        // Verify store contents
        let restored_shares = get_all_shares_from_store(&restore_store)
            .await
            .expect("failed to read dkg shares from db");
        assert_eq!(restored_shares.len(), expected_shares.len());

        // Use HashSet for order-independent comparison
        let original_shares_set: HashSet<model::EncryptedDkgShares> =
            expected_shares.into_iter().collect();
        let restored_shares_set: HashSet<model::EncryptedDkgShares> =
            restored_shares.into_iter().collect();
        assert_eq!(restored_shares_set, original_shares_set);
    }

    /// Tests that restore fails if keys mismatch and the `force` flag is false.
    ///
    /// Creates a backup with one key, attempts restore with a different key (force=false),
    /// and verifies it fails with `SignatureMismatchRequiresForce` and the store remains empty.
    #[tokio::test]
    async fn restore_key_mismatch_requires_force() {
        let mut rng = get_rng();
        let temp_dir = tempdir().unwrap();
        let backup_path = temp_dir.path().join("restore_mismatch_noforce.bin");

        let backup_signing_key = PrivateKey::new(&mut rng); // Key used for backup
        let restore_signer_key = PrivateKey::new(&mut rng); // Different key for restore context
        assert_ne!(backup_signing_key, restore_signer_key);

        // Create the original "backed up" shares with a single verified share
        let original_shares = vec![model::EncryptedDkgShares {
            dkg_shares_status: model::DkgSharesStatus::Verified,
            ..Faker.fake_with_rng(&mut rng)
        }];

        // Create backup file signed with backup_signing_key
        create_test_backup_file(&backup_path, &backup_signing_key, original_shares.clone()).await;

        // Setup restore context with restore_signer_key (different key)
        let restore_store = Store::new_shared();

        // Perform restore (force = false) - Expect error
        let result = restore_backup(&restore_store, &restore_signer_key, &backup_path, false).await;
        assert!(result.is_err());

        // Verify the specific error
        match result.err().unwrap() {
            RestoreError::SignatureMismatchRequiresForce(path, backup_pk, current_pk) => {
                assert_eq!(path, backup_path);
                assert_eq!(backup_pk, PublicKey::from_private_key(&backup_signing_key));
                assert_eq!(current_pk, PublicKey::from_private_key(&restore_signer_key));
            }
            e => panic!("Expected SignatureMismatchRequiresForce, got {:?}", e),
        }

        // Verify store is still empty
        let shares_in_store = get_all_shares_from_store(&restore_store)
            .await
            .expect("failed to read dkg shares from db");
        assert!(shares_in_store.is_empty());
    }

    /// Tests successful restore despite key mismatch when the `force` flag is true.
    ///
    /// Creates a backup with one key, attempts restore with a different key (force=true),
    /// and verifies it succeeds and the store contains the correct shares.
    #[tokio::test]
    async fn restore_key_mismatch_with_force_success() {
        let mut rng = get_rng();
        let temp_dir = tempdir().unwrap();
        let backup_path = temp_dir.path().join("restore_mismatch_force.bin");

        let backup_signing_key = PrivateKey::new(&mut rng); // Key used for backup
        let restore_signer_key = PrivateKey::new(&mut rng); // Different key for restore context
        assert_ne!(backup_signing_key, restore_signer_key);

        // Need to make sure the shares are verified
        let original_shares = vec![model::EncryptedDkgShares {
            dkg_shares_status: model::DkgSharesStatus::Verified,
            ..Faker.fake_with_rng(&mut rng)
        }];

        // Create backup file signed with backup_signing_key
        create_test_backup_file(&backup_path, &backup_signing_key, original_shares.clone()).await;

        // Setup restore context with restore_signer_key (different key)
        let restore_store = Store::new_shared();

        // Perform restore (force = false) - Expect error
        let restore_result =
            restore_backup(&restore_store, &restore_signer_key, &backup_path, false).await;
        assert!(
            restore_result.is_err(),
            "expected restore without force to fail due to signature mismatch"
        );

        // Perform restore (force = true) - Expect success
        restore_backup(&restore_store, &restore_signer_key, &backup_path, true)
            .await
            .expect("expected restore with force to succeed"); // Use expect to handle error

        // Verify store contents (should be restored despite key mismatch)
        let restored_shares = get_all_shares_from_store(&restore_store)
            .await
            .expect("failed to read dkg shares from db");

        // This assertion should now pass because the backup file contains 1 share
        assert_eq!(restored_shares.len(), original_shares.len());
        let original_shares_set: HashSet<model::EncryptedDkgShares> =
            original_shares.into_iter().collect(); // Use model type
        let restored_shares_set: HashSet<model::EncryptedDkgShares> =
            restored_shares.into_iter().collect(); // Use model type
        assert_eq!(restored_shares_set, original_shares_set);
    }

    /// Tests that restore fails if the backup signature is invalid/corrupted.
    ///
    /// Creates a valid backup, tampers with the signature bytes, attempts restore
    /// with the original key, and verifies it fails with `SignatureVerificationFailed`.
    #[tokio::test]
    async fn restore_signature_corrupt_same_key() {
        let mut rng = get_rng();
        let temp_dir = tempdir().expect("failed to create temp dir");
        let backup_path = temp_dir.path().join("restore_corrupt.bin");

        let signer_key = PrivateKey::new(&mut rng);

        // Create the original "backed up" shares
        let original_shares = vec![Faker.fake_with_rng(&mut rng)];

        // Create a valid backup file
        create_test_backup_file(&backup_path, &signer_key, original_shares.clone()).await;

        // Read, tamper, write back
        let backup_bytes = tokio::fs::read(&backup_path)
            .await
            .expect("failed to read backup file");
        let mut decoded_backup =
            BackupFile::decode(backup_bytes.as_slice()).expect("failed to decode backup file");
        let mut header = decoded_backup
            .header
            .ok_or("Missing header")
            .expect("header missing");
        let mut signature_proto = header.signature.expect("signature missing");

        // Temper with the signature
        if let Some(sig_part) = signature_proto.lower_bits.as_mut() {
            // Adjust field name if needed
            sig_part.bits_part0 ^= 0x01;
        } else {
            panic!("Signature part (e.g., lower_bits) was None, cannot tamper");
        }

        header.signature = Some(signature_proto);
        decoded_backup.header = Some(header);
        tokio::fs::write(&backup_path, decoded_backup.encode_to_vec())
            .await
            .expect("failed to write back tampered file");

        // Setup restore context with the original key
        let restore_store = Store::new_shared();

        // Perform restore (force = false) - Expect error
        assert_matches!(
            restore_backup(&restore_store, &signer_key, &backup_path, false).await,
            Err(RestoreError::SignatureVerificationFailed(_)),
            "expected signature verification failure"
        );

        // Verify store is still empty
        let shares_in_store = get_all_shares_from_store(&restore_store)
            .await
            .expect("failed to read dkg shares from db");
        assert!(shares_in_store.is_empty());
    }

    /// Tests that restore fails correctly if the backup file does not exist.
    ///
    /// Attempts to restore from a non-existent path and verifies it fails with
    /// `RestoreError::ReadFailed` and the inner error kind is `NotFound`.
    #[tokio::test]
    async fn restore_file_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = get_rng();
        let temp_dir = tempdir()?;
        let backup_path = temp_dir.path().join("non_existent_backup.bin"); // Should not exist

        let signer_key = PrivateKey::new(&mut rng);
        let restore_store = Store::new_shared();

        // Attempt to restore from a non-existent file
        assert_matches!(
            restore_backup(&restore_store, &signer_key, &backup_path, false).await,
            Err(RestoreError::ReadFailed(path, err)) => {
                assert_eq!(path, backup_path);
                assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
            },
            "expected ReadFailed error"
        );
        Ok(())
    }

    /// Tests that restore fails correctly if the backup file contains invalid protobuf data.
    ///
    /// Writes arbitrary bytes to a file, attempts restore, and verifies it fails
    /// with `RestoreError::DecodeFailed`.
    #[tokio::test]
    async fn restore_decode_error() {
        let temp_dir = tempdir().expect("failed to create temp dir");
        let backup_path = temp_dir.path().join("invalid_proto.bin");

        // Write invalid bytes to the file
        tokio::fs::write(&backup_path, b"this is not valid protobuf data")
            .await
            .expect("failed to write invalid data");

        let signer_key = PrivateKey::new(&mut get_rng());
        let restore_store = Store::new_shared();

        // Attempt to restore from the invalid file
        assert_matches!(
            restore_backup(&restore_store, &signer_key, &backup_path, false).await,
            Err(RestoreError::DecodeFailed(path, _)) => {
                assert_eq!(path, backup_path);
            },
            "expected DecodeFailed error"
        );
    }

    /// Tests that restore fails correctly if the backup file has an incorrect format version.
    ///
    /// Creates a valid backup, modifies the version in the header, attempts restore,
    /// and verifies it fails with `RestoreError::InvalidFormatVersion`.
    #[tokio::test]
    async fn restore_invalid_version() {
        let mut rng = get_rng();
        let temp_dir = tempdir().expect("failed to create temp dir");
        let backup_path = temp_dir.path().join("invalid_version.bin");

        let signer_key = PrivateKey::new(&mut rng);
        let original_shares = vec![Faker.fake_with_rng(&mut rng)];

        // Create a valid backup file
        create_test_backup_file(&backup_path, &signer_key, original_shares.clone()).await;

        // Read, change version, write back
        let backup_bytes = tokio::fs::read(&backup_path)
            .await
            .expect("failed to read backup file");
        let mut decoded_backup =
            BackupFile::decode(backup_bytes.as_slice()).expect("failed to decode backup file");
        let mut header = decoded_backup.header.expect("missing header");
        let invalid_version = BACKUP_FILE_VERSION + 1;
        header.format_version = invalid_version; // Set wrong version
        decoded_backup.header = Some(header);
        tokio::fs::write(&backup_path, decoded_backup.encode_to_vec())
            .await
            .expect("failed to write back backup file");

        // Setup restore context
        let restore_store = Store::new_shared();

        // Perform restore - Expect error
        assert_matches!(
            restore_backup(&restore_store, &signer_key, &backup_path, false).await,
            Err(RestoreError::InvalidFormatVersion(path, found, expected)) => {
                assert_eq!(path, backup_path);
                assert_eq!(found, invalid_version);
                assert_eq!(expected, BACKUP_FILE_VERSION);
            },
            "expected InvalidFormatVersion error"
        );
    }
}
