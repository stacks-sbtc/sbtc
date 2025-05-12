//! Error types for the CLI module.

/// Error types for the CLI module.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// An error occurred while attempting to back up the signer state.
    #[error(transparent)]
    BackupSignerState(#[from] crate::cli::backups::BackupError),

    /// An error occurred while attempting to restore the signer state from a backup.
    #[error(transparent)]
    RestoreSignerState(#[from] crate::cli::backups::RestoreError),
}
