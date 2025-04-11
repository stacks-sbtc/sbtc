use std::path::{Path, PathBuf};

use prost::Message;
use secp256k1::{
    Message as SecpMessage,                     // Alias for clarity
    hashes::{Hash, sha256::Hash as Sha256Hash}, // Use specific Hash type
};
use tokio::io::AsyncWriteExt;

use crate::{
    backups::BACKUP_FILE_VERSION,
    context::Context,
    keys::PublicKey,
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

    /// Error when accessing database
    #[error("database error: {0}")]
    Database(#[source] Box<crate::error::Error>),

    /// Failed to convert a type during the backup process.
    #[error("type conversion: {0}: {1}")]
    ProtoConvert(&'static str, #[source] Box<crate::error::Error>),
}

/// Creates a backup of the current state of the signer and saves it to the specified path.
#[allow(unused)]
pub async fn backup_signer<P>(ctx: &impl Context, path: P) -> Result<(), BackupError>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();
    tracing::info!(path = %path.display(), "beginning signer state backup");

    // --- Steps ---
    // 1. Generate BackupFileBody
    // 2. Serialize BackupFileBody
    // 3. Hash serialized BackupFileBody (SHA-256)
    // 4. Sign the hash using the signer's private key
    // 5. Create BackupFileHeader (version, timestamp, revision, public_key, signature)
    // 6. Assemble BackupFile (header, body)
    // 7. Serialize BackupFile
    // 8. Persist serialized BackupFile

    // 1. Generate the body content
    let body = generate_backup(ctx).await?;

    // 2. Serialize body for signing
    let body_bytes = body.encode_to_vec();

    // 3. Hash the serialized body (using SHA-256)
    let body_hash = Sha256Hash::hash(&body_bytes);
    let message_to_sign =
        SecpMessage::from_digest_slice(&body_hash[..]).map_err(BackupError::Signing)?;

    // 4. Sign the hash
    let signer_private_key = ctx.config().signer.private_key;
    let signature = signer_private_key.sign_ecdsa(&message_to_sign);

    // 5. Create the header
    let signer_public_key = PublicKey::from_private_key(&signer_private_key);
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

    // 6. Assemble the final backup file message
    let backup_file = backups::BackupFile {
        header: Some(header),
        body: Some(body),
    };

    // 7 & 8. Serialize and Persist to disk
    persist_backup(path, backup_file).await?;
    tracing::info!(path = %path.display(), "signer state backup completed successfully");
    Ok(())
}

/// Generates a backup of the current state of the signer.
#[allow(unused)]
async fn generate_backup(ctx: &impl Context) -> Result<BackupFileBody, BackupError> {
    let storage = ctx.get_storage();

    // Fetch and convert DKG shares
    let dkg_shares = storage
        .get_all_encrypted_dkg_shares()
        .await
        .map_err(|e| BackupError::Database(Box::new(e)))?
        .into_iter()
        .filter(|shares| shares.dkg_shares_status == model::DkgSharesStatus::Verified)
        .map(|db_share| db_share.into())
        .collect::<Vec<backups::DkgShares>>();

    tracing::debug!(count = dkg_shares.len(), "fetched and converted DKG shares");

    // Construct the body only with DKG shares
    Ok(BackupFileBody { dkg_shares })
}

/// Persists the encoded backup file to the specified path asynchronously.
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
        backups::testing::setup_test_context,
        keys::{PrivateKey, PublicKey},
        proto::sbtc::signer::v1::backups::{self as backups_proto, BackupFile},
        testing::get_rng,
    };
    use bitcoin::hashes::Hash as BitcoinHash;
    use fake::{Fake, Faker};
    use prost::Message;
    use secp256k1::{Message as SecpMessage, Secp256k1, hashes::sha256};
    use tempfile::tempdir;
    use test_case::test_case;
    use time::OffsetDateTime;

    #[tokio::test]
    async fn backup_signer_success() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = get_rng();
        let temp_dir = tempdir()?;
        let backup_path = temp_dir.path().join("test_backup.bin");

        // --- Setup Context ---
        let signer_private_key = PrivateKey::new(&mut rng);
        let signer_public_key = PublicKey::from_private_key(&signer_private_key);
        let mock_dkg_share_data = vec![Faker.fake_with_rng(&mut rng)];

        let ctx = setup_test_context(signer_private_key, mock_dkg_share_data.clone()).await;

        let start_time = OffsetDateTime::now_utc().unix_timestamp() as u64;

        backup_signer(&ctx, &backup_path).await?;

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
        // Check timestamp is recent (within a small window)
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
        // Compare the first share (requires From impl and PartialEq)
        let expected_proto_share: backups_proto::DkgShares = mock_dkg_share_data[0].clone().into();
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

    #[tokio::test]
    async fn backup_signer_file_exists() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = get_rng();
        let temp_dir = tempdir()?;
        let backup_path = temp_dir.path().join("existing_backup.bin");

        // Create an empty file beforehand
        tokio::fs::File::create(&backup_path).await?;

        // Setup minimal context
        let signer_private_key = PrivateKey::new(&mut rng);
        // No shares needed as it should fail before storage access
        let ctx = setup_test_context(signer_private_key, vec![]).await;

        // Execute and verify error
        let result = backup_signer(&ctx, &backup_path).await;
        assert!(result.is_err());
        match result.err().unwrap() {
            BackupError::FileAlreadyExists(p) => assert_eq!(p, backup_path),
            e => panic!("Expected FileAlreadyExists error, got {:?}", e),
        }
        Ok(())
    }

    // Add more tests using test_case if needed for different scenarios
    // e.g., empty storage, multiple shares, etc.
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

        let signer_private_key = PrivateKey::new(&mut rng);
        let shares: Vec<_> = (0..num_shares)
            .map(|_| Faker.fake_with_rng(&mut rng))
            .collect();

        let ctx = setup_test_context(signer_private_key, shares.clone()).await;

        backup_signer(&ctx, &backup_path).await?;

        let backup_bytes = tokio::fs::read(&backup_path).await?;
        let decoded_backup = BackupFile::decode(backup_bytes.as_slice())?;
        let body = decoded_backup.body.ok_or("Backup body missing")?;

        assert_eq!(body.dkg_shares.len(), num_shares);

        if num_shares > 0 {
            let expected_proto_shares: Vec<_> = shares.into_iter().map(|s| s.into()).collect();
            let actual_shares = &body.dkg_shares; // Borrow the vec from body

            // Check that every expected share exists in the actual shares
            for expected_share in &expected_proto_shares {
                assert!(
                    actual_shares.contains(expected_share),
                    "Backup is missing an expected share: {:?}",
                    expected_share
                );
            }
        }

        Ok(())
    }
}
