use std::path::{Path, PathBuf};

use prost::Message;
use secp256k1::{
    Message as SecpMessage,
    Secp256k1, // Use specific Hash type
    hashes::{Hash, sha256::Hash as Sha256Hash},
};

use crate::{
    backups::BACKUP_FILE_VERSION,
    context::Context,
    keys::PublicKey,
    proto::sbtc::signer::v1::backups::BackupFile,
    storage::{DbRead, DbWrite, model},
};

/// Errors which can occur during the restore process.
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    /// Error reading backup file
    #[error("failed to read backup file '{0}': {1}.")]
    ReadFailed(PathBuf, #[source] std::io::Error),

    /// Error decoding backup file
    #[error("failed to decode backup file '{0}': {1}.")]
    DecodeFailed(PathBuf, #[source] prost::DecodeError),

    /// Invalid backup file version
    #[error("backup file '{0}' has invalid format version {1}, expected {2}.")]
    InvalidFormatVersion(PathBuf, u32, u32),

    /// Invalid backup file header
    #[error("backup file header is incomplete or invalid in '{0}'.")]
    InvalidHeader(PathBuf),

    /// Failed to sign backup body.
    #[error("failed to sign backup body: {0}.")]
    SigningFailed(#[from] secp256k1::Error),

    /// Invalid backup file signature
    #[error("signature verification failed for backup '{0}', data may be corrupt.")]
    SignatureVerificationFailed(PathBuf),

    /// Signature mismatch
    #[error(
        "backup file '{0}' was signed by a different key ({1}) than the current signer key ({2}). Use --force to restore anyway."
    )]
    SignatureMismatchRequiresForce(PathBuf, PublicKey, PublicKey),

    /// Error when reading from the database.
    #[error("database error: {0}")]
    DbRead(#[source] Box<crate::error::Error>),

    /// Error when writing to the database.
    #[error("failed to write data during restore from '{0}': {1}")]
    DbWrite(PathBuf, #[source] Box<crate::error::Error>),

    /// Failed to convert a type during the backup process.
    #[error("type conversion: {0}: {1}")]
    TypeConversion(
        &'static str,
        #[source] Box<dyn std::error::Error + Send + Sync>,
    ),

    /// Failed to convert between protobuf and model types.
    #[error("failed to convert data during restore from '{0}': {1}")]
    ProtoConvert(PathBuf, #[source] Box<crate::error::Error>),
}

/// Restores signer state from a backup file.
///
/// Reads the backup file, verifies its integrity and signature, and writes the
/// contained data to the signer's storage.
///
/// If the signature verification fails but the public key in the backup header
/// does not match the current signer's public key, it indicates a potential
/// key rotation. In this case, the restore will only proceed if `force` is true.
#[allow(unused)]
pub async fn restore_backup<P>(ctx: &impl Context, path: P, force: bool) -> Result<(), RestoreError>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();
    tracing::info!(path = %path.display(), force, "Beginning signer state restore.");

    // --- Steps ---
    // 1. Read backup file
    // 2. Decode BackupFile message
    // 3. Validate header (version, fields present)
    // 4. Verify signature
    // 5. Handle signature mismatch (check keys, check force flag)
    // 6. Restore data (convert proto -> model, write to storage)

    // 1. Read backup file
    let backup_bytes = tokio::fs::read(path)
        .await
        .map_err(|e| RestoreError::ReadFailed(path.to_path_buf(), e))?;
    tracing::debug!(path = %path.display(), bytes = backup_bytes.len(), "Read backup file.");

    // 2. Decode BackupFile message
    let decoded_backup = BackupFile::decode(backup_bytes.as_slice())
        .map_err(|e| RestoreError::DecodeFailed(path.to_path_buf(), e))?;
    tracing::debug!(path = %path.display(), "Decoded backup file.");

    // 3. Validate header
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
    // Assuming TryFrom implementations exist in proto::convert
    let backup_public_key: PublicKey = backup_public_key_proto
        .try_into()
        .map_err(|e| RestoreError::ProtoConvert(path.to_path_buf(), Box::new(e)))?;
    let signature: secp256k1::ecdsa::Signature = signature_proto
        .try_into()
        .map_err(|e| RestoreError::ProtoConvert(path.to_path_buf(), Box::new(e)))?;
    tracing::debug!(path = %path.display(), key = %backup_public_key, "extracted header fields");

    // Get current key for comparison
    let current_public_key = PublicKey::from_private_key(&ctx.config().signer.private_key);

    // 4. Verify signature
    let body = decoded_backup
        .body
        .ok_or_else(|| RestoreError::InvalidHeader(path.to_path_buf()))?; // Body needed for verification

    let body_bytes_for_verify = body.encode_to_vec();
    let body_hash = Sha256Hash::hash(&body_bytes_for_verify);
    let msg =
        SecpMessage::from_digest_slice(&body_hash[..]).map_err(RestoreError::SigningFailed)?; // Reuse SigningFailed or create specific error

    let secp = Secp256k1::verification_only();
    match secp.verify_ecdsa(&msg, &signature, &backup_public_key) {
        Ok(_) => {
            tracing::info!(path = %path.display(), "backup signature verified successfully against header key.");
            // Signature is valid according to the key in the backup file.
            // NOW, check if that key matches the current signer's key.
            if backup_public_key != current_public_key {
                tracing::warn!(path = %path.display(), backup_key = %backup_public_key, current_key = %current_public_key, "backup key differs from current signer key.");
                if !force {
                    // Keys differ and force is not set, return error.
                    return Err(RestoreError::SignatureMismatchRequiresForce(
                        path.to_path_buf(),
                        backup_public_key,
                        current_public_key,
                    ));
                } else {
                    // Keys differ, but force is set, proceed with warning.
                    tracing::warn!(path = %path.display(), "--force flag provided, proceeding with restore despite key mismatch.");
                }
            }
            // Keys match, or keys differ but force=true. Proceed to restore.
        }
        Err(e) => {
            // Signature is invalid according to the key in the backup file.
            // This implies corruption or a bug, regardless of the current key or force flag.
            tracing::warn!(path = %path.display(), error = %e, "backup signature verification failed against header key.");
            return Err(RestoreError::SignatureVerificationFailed(
                path.to_path_buf(),
            ));
        }
    }

    // 6. Restore data
    let storage = ctx.get_storage_mut();
    tracing::info!(path = %path.display(), count = body.dkg_shares.len(), "starting data restore to storage.");

    for proto_share in body.dkg_shares {
        // Convert proto share back to model share
        // Assuming TryFrom<proto::DkgShares> for model::EncryptedDkgShares exists
        let model_share: model::EncryptedDkgShares = proto_share
            .try_into()
            .map_err(|e| RestoreError::ProtoConvert(path.to_path_buf(), Box::new(e)))?;

        let existing = storage
            .get_encrypted_dkg_shares(&model_share.aggregate_key)
            .await
            .map_err(|e| RestoreError::DbRead(Box::new(e)))?;

        if let Some(shares) = existing {
            tracing::warn!(aggregate_key = %shares.aggregate_key, "found existing shares for aggregate key, skipping");
            continue;
        }

        // Write to storage
        tracing::info!(aggregate_key = %model_share.aggregate_key, "importing shares for aggregate key");
        storage
            .write_encrypted_dkg_shares(&model_share)
            .await
            .map_err(|e| RestoreError::DbWrite(path.to_path_buf(), Box::new(e)))?;
        // Note: Assumes StorageError can be the source for RestoreWriteFailed
    }

    tracing::info!(path = %path.display(), "Signer state restore completed successfully.");
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
        backups::{backup::backup_signer, testing::setup_test_context},
        keys::PrivateKey,
        storage::DbRead,
        testing::get_rng,
    };

    // Helper to create a valid backup file for testing restore
    async fn create_test_backup_file(
        backup_path: &Path,
        signing_key: PrivateKey,
        shares: Vec<model::EncryptedDkgShares>,
    ) {
        let backup_ctx = setup_test_context(signing_key, shares).await;
        backup_signer(&backup_ctx, backup_path)
            .await
            .expect("failed to create backup file");
    }

    // Helper to get all shares from store (for verification)
    async fn get_all_shares_from_store(
        store: &impl DbRead,
    ) -> Result<Vec<model::EncryptedDkgShares>, crate::error::Error> {
        store.get_all_encrypted_dkg_shares().await
    }

    #[tokio::test]
    async fn restore_success_matching_key() {
        let mut rng = get_rng();
        let temp_dir = tempdir().unwrap();
        let backup_path = temp_dir.path().join("restore_success.bin");

        let signer_key = PrivateKey::new(&mut rng);
        // Use helper to ensure status is Verified
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
        let expected_shares = original_shares
            .iter()
            .filter(|s| s.dkg_shares_status == model::DkgSharesStatus::Verified)
            .cloned()
            .collect::<Vec<_>>();

        // ... rest of the test ...
        // 1. Create the backup file using the signer key
        create_test_backup_file(&backup_path, signer_key, original_shares.clone()).await;

        // 2. Setup restore context with the SAME key and an EMPTY store
        let restore_ctx = setup_test_context(signer_key, vec![]).await; // Use setup_test_context
        let restore_store = restore_ctx.get_storage(); // Get handle to the empty store

        // 3. Perform restore (force = false)
        restore_backup(&restore_ctx, &backup_path, false)
            .await
            .expect("failed to restore backup");

        // 4. Verify store contents
        let restored_shares = get_all_shares_from_store(&restore_store)
            .await
            .expect("failed to read dkg shares from db");
        assert_eq!(restored_shares.len(), expected_shares.len());

        // Use HashSet for order-independent comparison
        let original_shares_set: HashSet<model::EncryptedDkgShares> =
            expected_shares.into_iter().collect(); // Use model type for HashSet
        let restored_shares_set: HashSet<model::EncryptedDkgShares> =
            restored_shares.into_iter().collect(); // Use model type for HashSet
        assert_eq!(restored_shares_set, original_shares_set);
    }

    #[tokio::test]
    async fn restore_key_mismatch_requires_force() {
        let mut rng = get_rng();
        let temp_dir = tempdir().unwrap();
        let backup_path = temp_dir.path().join("restore_mismatch_noforce.bin");

        let backup_signing_key = PrivateKey::new(&mut rng); // Key used for backup
        let restore_signer_key = PrivateKey::new(&mut rng); // Different key for restore context
        assert_ne!(backup_signing_key, restore_signer_key);
        // Use helper to ensure status is Verified
        let original_shares = vec![model::EncryptedDkgShares {
            dkg_shares_status: model::DkgSharesStatus::Verified,
            ..Faker.fake_with_rng(&mut rng)
        }];

        // 1. Create backup file signed with backup_signing_key
        create_test_backup_file(&backup_path, backup_signing_key, original_shares.clone()).await;

        // 2. Setup restore context with restore_signer_key (different key)
        let restore_ctx = setup_test_context(restore_signer_key, vec![]).await; // Use setup_test_context
        let restore_store = restore_ctx.get_storage();

        // 3. Perform restore (force = false) - Expect error
        let result = restore_backup(&restore_ctx, &backup_path, false).await;
        assert!(result.is_err());

        // 4. Verify the specific error
        match result.err().unwrap() {
            RestoreError::SignatureMismatchRequiresForce(path, backup_pk, current_pk) => {
                assert_eq!(path, backup_path);
                assert_eq!(backup_pk, PublicKey::from_private_key(&backup_signing_key));
                assert_eq!(current_pk, PublicKey::from_private_key(&restore_signer_key));
            }
            e => panic!("Expected SignatureMismatchRequiresForce, got {:?}", e),
        }

        // 5. Verify store is still empty
        let shares_in_store = get_all_shares_from_store(&restore_store)
            .await
            .expect("failed to read dkg shares from db");
        assert!(shares_in_store.is_empty());
    }

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

        // 1. Create backup file signed with backup_signing_key
        create_test_backup_file(&backup_path, backup_signing_key, original_shares.clone()).await;

        // 2. Setup restore context with restore_signer_key (different key)
        let restore_ctx = setup_test_context(restore_signer_key, vec![]).await;
        let restore_store = restore_ctx.get_storage();

        // 3. Perform restore (force = true) - Expect success
        let restore_result = restore_backup(&restore_ctx, &backup_path, false).await;
        assert!(
            restore_result.is_err(),
            "expected restore without force to fail due to signature mismatch"
        );
        restore_backup(&restore_ctx, &backup_path, true)
            .await
            .expect("expected restore with force to succeed"); // Use expect to handle error

        // 4. Verify store contents (should be restored despite key mismatch)
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

    #[tokio::test]
    async fn restore_signature_corrupt_same_key() {
        let mut rng = get_rng();
        let temp_dir = tempdir().expect("failed to create temp dir");
        let backup_path = temp_dir.path().join("restore_corrupt.bin");

        let signer_key = PrivateKey::new(&mut rng);
        // Use helper to ensure status is Verified
        let original_shares = vec![Faker.fake_with_rng(&mut rng)];

        // 1. Create a valid backup file
        create_test_backup_file(&backup_path, signer_key, original_shares.clone()).await;

        // 2. Read, tamper, write back
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

        // 3. Setup restore context with the original key
        let restore_ctx = setup_test_context(signer_key, vec![]).await;
        let restore_store = restore_ctx.get_storage();

        // 4. Perform restore (force = false) - Expect error
        assert_matches!(
            restore_backup(&restore_ctx, &backup_path, false).await,
            Err(RestoreError::SignatureVerificationFailed(_)),
            "expected signature verification failure"
        );

        // 5. Verify store is still empty
        let shares_in_store = get_all_shares_from_store(&restore_store)
            .await
            .expect("failed to read dkg shares from db");
        assert!(shares_in_store.is_empty());
    }

    #[tokio::test]
    async fn restore_file_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = get_rng();
        let temp_dir = tempdir()?;
        let backup_path = temp_dir.path().join("non_existent_backup.bin"); // Does not exist

        let signer_key = PrivateKey::new(&mut rng);
        let restore_ctx = setup_test_context(signer_key, vec![]).await;

        // Attempt to restore from a non-existent file
        assert_matches!(
            restore_backup(&restore_ctx, &backup_path, false).await,
            Err(RestoreError::ReadFailed(path, err)) => {
                assert_eq!(path, backup_path);
                assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
            },
            "expected ReadFailed error"
        );
        Ok(())
    }

    #[tokio::test]
    async fn restore_decode_error() {
        let temp_dir = tempdir().expect("failed to create temp dir");
        let backup_path = temp_dir.path().join("invalid_proto.bin");

        // Write invalid bytes to the file
        tokio::fs::write(&backup_path, b"this is not valid protobuf data")
            .await
            .expect("failed to write invalid data");

        let signer_key = PrivateKey::new(&mut get_rng());
        let restore_ctx = setup_test_context(signer_key, vec![]).await;

        // Attempt to restore from the invalid file
        assert_matches!(
            restore_backup(&restore_ctx, &backup_path, false).await,
            Err(RestoreError::DecodeFailed(path, _)) => {
                assert_eq!(path, backup_path);
            },
            "expected DecodeFailed error"
        );
    }

    #[tokio::test]
    async fn restore_invalid_version() {
        let mut rng = get_rng();
        let temp_dir = tempdir().expect("failed to create temp dir");
        let backup_path = temp_dir.path().join("invalid_version.bin");

        let signer_key = PrivateKey::new(&mut rng);
        let original_shares = vec![Faker.fake_with_rng(&mut rng)];

        // 1. Create a valid backup file
        create_test_backup_file(&backup_path, signer_key, original_shares.clone()).await;

        // 2. Read, change version, write back
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

        // 3. Setup restore context
        let restore_ctx = setup_test_context(signer_key, vec![]).await;

        // 4. Perform restore - Expect error
        assert_matches!(
            restore_backup(&restore_ctx, &backup_path, false).await,
            Err(RestoreError::InvalidFormatVersion(path, found, expected)) => {
                assert_eq!(path, backup_path);
                assert_eq!(found, invalid_version);
                assert_eq!(expected, BACKUP_FILE_VERSION);
            },
            "expected InvalidFormatVersion error"
        );
    }
}
