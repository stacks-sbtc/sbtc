//! Module handling backups of the signer state.

mod backup;
mod restore;

pub use backup::BackupError;
pub use backup::backup_signer;
pub use restore::RestoreError;
pub use restore::restore_backup;

/// The current version of the backup file format.
///
/// NOTE: Version 1 is the first version and the handling for future versions
/// is not explicitly defined. It is expected that potential future breaking
/// versions will implement the necessary logic for handling version 1 together
/// with new versions.
const BACKUP_FILE_VERSION: u32 = 1;
