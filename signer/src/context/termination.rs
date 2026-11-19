//! Module that contains termination-related code for the [`Context`].

/// Handle to the termination signal. This can be used to signal the application
/// to shutdown or to wait for a shutdown signal.
pub struct TerminationHandle(
    tokio::sync::watch::Sender<bool>,
    tokio::sync::watch::Receiver<bool>,
);

impl Clone for TerminationHandle {
    fn clone(&self) -> Self {
        Self(
            self.0.clone(),     // Sender
            self.0.subscribe(), // Receiver
        )
    }
}

impl TerminationHandle {
    /// Create a new termination handle.
    pub fn new(
        tx: tokio::sync::watch::Sender<bool>,
        rx: tokio::sync::watch::Receiver<bool>,
    ) -> Self {
        Self(tx, rx)
    }

    /// Check if a shutdown signal has been signalled.
    pub fn shutdown_signalled(&self) -> bool {
        *self.1.borrow()
    }

    /// Signal the application to shutdown.
    pub fn signal_shutdown(&self) {
        // We ignore the result here, as if all receivers have been dropped,
        // we're on our way down anyway.
        self.0.send_if_modified(|x| {
            if !(*x) {
                *x = true;
                true
            } else {
                false
            }
        });
    }
    /// Wait until shutdown is signalled, returning immediately if it
    /// already has been.
    pub async fn wait_for_shutdown(&mut self) {
        // Check the current value as well as future changes so late
        // subscribers cannot miss shutdown. The channel cannot close while
        // we hold a sender.
        let _ = self.1.wait_for(|shutdown| *shutdown).await;
    }
}
