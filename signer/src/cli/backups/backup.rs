//! Handles the creation and persistence of encrypted signer state backups.
//!
//! This module provides functionality to generate a backup file containing critical
//! signer state (like DKG shares), sign it with the signer's private key, and
//! write it to disk.

use std::path::{Path, PathBuf};

use prost::Message;
use secp256k1::{
    Message as SecpMessage,
    hashes::{Hash, sha256::Hash as Sha256Hash},
};
use tokio::io::AsyncWriteExt;

use crate::{
    cli::backups::BACKUP_FILE_VERSION,
    keys::{PrivateKey, PublicKey},
    proto::{
        self, EcdsaSignature,
        sbtc::signer::v1::backups::{self, BackupFile, BackupFileBody, BackupFileHeader},
    },
    storage::{DbRead, model},
};

/// Errors which can occur during the backup process.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// The backup file already exists at the target path.
    #[error("file already exists at backup target path '{0}'.")]
    FileAlreadyExists(PathBuf),

    /// Failed to create the backup file at the target path.
    #[error("failed to create backup file '{0}': {1}.")]
    FileCreation(#[source] std::io::Error, PathBuf),

    /// Failed to write the backup file at the target path.
    #[error("failed to write backup file '{0}': {1}.")]
    FileWrite(#[source] std::io::Error, PathBuf),

    /// Failed to sign backup body.
    #[error("failed to sign backup body: {0}.")]
    Signing(#[from] secp256k1::Error),

    /// Error when accessing database.
    #[error("database error: {0}")]
    Database(#[source] Box<crate::error::Error>),

    /// Failed to convert a type during the backup process.
    #[error("type conversion: {0}: {1}")]
    ProtoConvert(&'static str, #[source] Box<crate::error::Error>),
}

/// Creates a backup of the current signer state and saves it to the specified path.
///
/// This function gathers relevant state (currently verified DKG shares), signs the
/// serialized state using the provided `signer_private_key`, constructs a `BackupFile`
/// containing a header (with version, timestamp, public key, signature) and the body,
/// and finally persists the encoded `BackupFile` to the given `path`.
///
/// # Arguments
/// * `ctx` - A database context implementing `DbRead` to fetch state.
/// * `signer_private_key` - The private key used to sign the backup body.
/// * `path` - The file system path where the backup file will be created.
///
/// # Errors
/// Returns `BackupError` if any step fails, including database access, signing,
/// or file I/O operations. It specifically returns `BackupError::FileAlreadyExists`
/// if a file already exists at the target `path`.
#[allow(unused)]
pub async fn backup_signer<P>(
    ctx: &impl DbRead,
    signer_private_key: &PrivateKey,
    path: P,
) -> Result<(), BackupError>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();

    // Generate the body content
    let body = generate_backup_body(ctx).await?;

    // Serialize body for signing
    let body_bytes = body.encode_to_vec();

    // Hash the serialized body (using SHA-256)
    let body_hash = Sha256Hash::hash(&body_bytes);
    let message_to_sign =
        SecpMessage::from_digest_slice(&body_hash[..]).map_err(BackupError::Signing)?;

    // Sign the hash
    let signature = signer_private_key.sign_ecdsa(&message_to_sign);

    // Create the header
    let signer_public_key = PublicKey::from_private_key(signer_private_key);
    let unix_timestamp = time::OffsetDateTime::now_utc().unix_timestamp() as u64;

    // Convert internal PublicKey and Signature to proto types
    let proto_public_key: proto::PublicKey = signer_public_key.into();
    let proto_signature: EcdsaSignature = signature.into();

    // Build the header instance
    let header = BackupFileHeader {
        format_version: BACKUP_FILE_VERSION,
        unix_timestamp,
        software_revision: crate::GIT_COMMIT.to_string(),
        public_key: Some(proto_public_key),
        signature: Some(proto_signature),
    };

    // Assemble the final backup file message
    let backup_file = backups::BackupFile {
        header: Some(header),
        body: Some(body),
    };

    // Serialize and Persist to disk
    persist_backup(path, backup_file).await?;
    Ok(())
}

/// Generates the body content for the backup file.
///
/// Currently, this fetches all encrypted DKG shares from storage, filters them
/// to include only those marked as `Verified`, and converts them into the
/// protobuf format (`backups::DkgShares`).
///
/// # Arguments
/// * `storage` - A database context implementing `DbRead`.
///
/// # Errors
/// Returns `BackupError::Database` if fetching shares fails.
#[allow(unused)]
async fn generate_backup_body(storage: &impl DbRead) -> Result<BackupFileBody, BackupError> {
    // Fetch, filter and convert DKG shares from the database into the proto format
    let dkg_shares = storage
        .get_all_encrypted_dkg_shares()
        .await
        .map_err(|e| BackupError::Database(Box::new(e)))?
        .into_iter()
        .filter(|shares| shares.dkg_shares_status == model::DkgSharesStatus::Verified)
        .map(|db_share| db_share.into())
        .collect::<Vec<backups::DkgShares>>();

    // Construct the body only with DKG shares
    Ok(BackupFileBody { dkg_shares })
}

/// Encodes the `BackupFile` message and persists it to the specified path.
///
/// This function attempts to create a new file exclusively at the given path.
/// If the file already exists, it returns `BackupError::FileAlreadyExists`.
/// Otherwise, it writes the encoded `BackupFile` bytes asynchronously and ensures
/// the data is flushed to the disk.
///
/// # Arguments
/// * `path` - The file system path where the backup file will be created.
/// * `backup_file` - The `BackupFile` protobuf message to encode and save.
///
/// # Errors
/// Returns `BackupError::FileAlreadyExists` if the file exists.
/// Returns `BackupError::FileCreation` if the file cannot be created.
/// Returns `BackupError::FileWrite` if writing or syncing the file fails.
#[allow(unused)]
async fn persist_backup<P>(path: P, backup_file: BackupFile) -> Result<(), BackupError>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();

    // Encode the final message
    let file_bytes = backup_file.encode_to_vec();

    // Try to create the file
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true) // Fails if the file already exists
        .open(path)
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                BackupError::FileAlreadyExists(path.to_path_buf())
            } else {
                BackupError::FileCreation(e, path.to_path_buf())
            }
        })?;

    // Write data asynchronously
    file.write_all(&file_bytes)
        .await
        .map_err(|e| BackupError::FileWrite(e, path.to_path_buf()))?;

    // Ensure data is written to disk asynchronously
    file.sync_all()
        .await
        .map_err(|e| BackupError::FileWrite(e, path.to_path_buf()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        keys::{PrivateKey, PublicKey},
        proto::sbtc::signer::v1::backups::{self as backups_proto, BackupFile},
        storage::{DbWrite, in_memory::Store},
        testing::get_rng,
    };
    use assert_matches::assert_matches;
    use bitcoin::hashes::Hash as BitcoinHash;
    use fake::{Fake, Faker};
    use prost::Message;
    use secp256k1::{Message as SecpMessage, Secp256k1, hashes::sha256};
    use tempfile::tempdir;
    use test_case::test_case;
    use time::OffsetDateTime;

    /// Tests the successful creation of a backup file.
    ///
    /// Verifies that:
    /// - A backup file is created at the specified path.
    /// - The file is not empty.
    /// - The decoded file contains a valid header (version, revision, public key, timestamp).
    /// - The decoded file contains the correct body (verified DKG shares).
    /// - The signature in the header correctly verifies against the body hash and public key.
    #[tokio::test]
    async fn backup_signer_success() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = get_rng();
        let temp_dir = tempdir()?;
        let backup_path = temp_dir.path().join("test_backup.bin");

        let signer_private_key = PrivateKey::new(&mut rng);
        let signer_public_key = PublicKey::from_private_key(&signer_private_key);
        let shares = vec![model::EncryptedDkgShares {
            dkg_shares_status: model::DkgSharesStatus::Verified,
            ..Faker.fake_with_rng(&mut rng)
        }];

        let store = Store::new_shared();
        for share in &shares {
            store.write_encrypted_dkg_shares(share).await.unwrap();
        }

        let start_time = OffsetDateTime::now_utc().unix_timestamp() as u64;

        backup_signer(&store, &signer_private_key, &backup_path).await?;

        assert!(backup_path.exists(), "Backup file was not created");

        let backup_bytes = tokio::fs::read(&backup_path).await?;
        assert!(!backup_bytes.is_empty(), "Backup file is empty");

        let decoded_backup = BackupFile::decode(backup_bytes.as_slice())?;

        // Verify Header
        let header = decoded_backup
            .header
            .ok_or("Backup file header is missing")?;
        assert_eq!(header.format_version, BACKUP_FILE_VERSION);
        assert_eq!(header.software_revision, crate::GIT_COMMIT);
        let header_pk: PublicKey = header
            .public_key
            .ok_or("Header public key missing")?
            .try_into() // Assumes TryFrom<proto::PublicKey> for PublicKey exists
            .map_err(|e| format!("Failed to convert header public key: {:?}", e))?;
        assert_eq!(header_pk, signer_public_key);

        // Check timestamp is recent (within a small window), just to make sure
        // we're setting it correctly
        assert!(
            header.unix_timestamp >= start_time && header.unix_timestamp <= start_time + 5,
            "Timestamp {} out of range ({}-{})",
            header.unix_timestamp,
            start_time,
            start_time + 5
        );

        // Verify Body
        let body = decoded_backup.body.ok_or("Backup file body is missing")?;
        assert_eq!(
            body.dkg_shares.len(),
            1,
            "Incorrect number of DKG shares in backup"
        );

        // Compare the first share
        let expected_proto_share: backups_proto::DkgShares = shares[0].clone().into();
        assert_eq!(body.dkg_shares[0], expected_proto_share);

        // Verify Signature
        let signature: secp256k1::ecdsa::Signature = header
            .signature
            .ok_or("Header signature missing")?
            .try_into() // Assumes TryFrom<proto::EcdsaSignature> for secp sig exists
            .map_err(|e| format!("Failed to convert header signature: {:?}", e))?;

        let body_bytes_for_verify = body.encode_to_vec();
        let body_hash = sha256::Hash::hash(&body_bytes_for_verify);
        let msg = SecpMessage::from_digest_slice(&body_hash[..])?;

        let secp = Secp256k1::verification_only();
        secp.verify_ecdsa(&msg, &signature, &signer_public_key)?;

        Ok(())
    }

    /// Tests that `backup_signer` returns `BackupError::FileAlreadyExists` if the target file exists.
    ///
    /// Creates an empty file at the target path before calling `backup_signer` and
    /// asserts that the specific error variant is returned.
    #[tokio::test]
    async fn backup_signer_file_exists() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = get_rng();
        let temp_dir = tempdir()?;
        let backup_path = temp_dir.path().join("existing_backup.bin");

        // Create a new store
        let store = Store::new_shared();

        // Create an empty file beforehand
        tokio::fs::File::create(&backup_path).await?;

        // Generate a new private key for the signer
        let signer_private_key = PrivateKey::new(&mut rng);

        // Execute and verify error
        assert_matches!(
            backup_signer(&store, &signer_private_key, &backup_path).await,
            Err(BackupError::FileAlreadyExists(_))
        );

        Ok(())
    }

    /// Tests backup creation with varying numbers of DKG shares using `test_case`.
    ///
    /// Verifies that the number of shares included in the final backup file body
    /// correctly matches the number of shares initially stored with a `Verified` status.
    /// Also checks that the content of the included shares matches the expected content.
    #[test_case(0; "no shares")]
    #[test_case(1; "one share")]
    #[test_case(2; "two shares")]
    #[test_case(20; "twenty shares")]
    #[tokio::test]
    async fn backup_signer_share_count(
        num_shares: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = get_rng();
        let temp_dir = tempdir()?;
        let backup_path = temp_dir.path().join(format!("backup_{}.bin", num_shares));

        // Generate private key for the signer
        let signer_private_key = PrivateKey::new(&mut rng);

        // Generate random shares
        let shares: Vec<_> = (0..num_shares)
            .map(|_| Faker.fake_with_rng(&mut rng))
            .collect();

        // Create a new store and write the shares to it
        let store = Store::new_shared();
        for share in &shares {
            store.write_encrypted_dkg_shares(share).await.unwrap();
        }

        // Execute the backup
        backup_signer(&store, &signer_private_key, &backup_path).await?;

        // Read back the file
        let backup_bytes = tokio::fs::read(&backup_path).await?;

        // Decode the file and ensure the body is present
        let decoded_backup = BackupFile::decode(backup_bytes.as_slice())?;
        let body = decoded_backup.body.ok_or("Backup body missing")?;

        // Determine the expected shares based on the status (only verified shares
        // should be included in the backup file, and we've generated them completely
        // randomly above)
        let expected_proto_shares = shares
            .into_iter()
            .filter_map(|share| match share.dkg_shares_status {
                model::DkgSharesStatus::Verified => Some(backups_proto::DkgShares::from(share)),
                _ => None,
            })
            .collect::<Vec<_>>();

        // Assert that the number of expected shares match the number of shares in the body
        assert_eq!(body.dkg_shares.len(), expected_proto_shares.len());

        // Check that every expected share exists in the actual shares
        for expected_share in &expected_proto_shares {
            assert!(
                &body.dkg_shares.contains(expected_share),
                "Backup is missing an expected share: {expected_share:?}"
            );
        }

        Ok(())
    }
}
