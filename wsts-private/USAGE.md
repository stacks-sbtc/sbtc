# Usage

Applications which use `WSTS` will typically run both `Signer` and `Coordinator` state machines, in order to be able to handle all parts of the protocol.  Because of this, these state machines do not verify packets as they come in; this would lead to duplicate work, and require the state machines to have all keys in their configs, including knowing who is the active coordinator.  This is out of scope for the library.  Thus applications `must` verify packets before calling `process_message` on them.

This addresses the audit critical issues [CR-01](https://github.com/Trust-Machines/wsts/issues/66) and [CR-02](https://github.com/Trust-Machines/wsts/issues/67).