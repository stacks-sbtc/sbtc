# Usage

Applications which use `WSTS` will typically run both `Signer` and `Coordinator` state machines, in order to be able to handle all parts of the protocol. Because of this, these state machines do not verify packets as they come in; this would lead to duplicate work, and require the state machines to have all keys in their configs, including knowing who is the active coordinator. This is out of scope for the library. Thus applications `must` verify packets before calling `process_message` on them.

This addresses the audit critical issues [CR-01](https://github.com/Trust-Machines/wsts/issues/66) and [CR-02](https://github.com/Trust-Machines/wsts/issues/67).


To ensure flexibility, these state machines require the user to provide a random number generator (RNG) that implements the `RngCore` and `CryptoRng` traits.

### Providing an RNG

You can use the following RNG implementations:

- **Operating System RNG (`OsRng`)**
  
  ```rust
  use rand_core::OsRng;

  let mut rng = OsRng;
  ```

- **ChaCha20 RNG**
  
  ```rust
  use rand_chacha::ChaCha20Rng;

  let mut rng = ChaCha20Rng::from_entropy();
  ```

- **Custom RNGs**

  Implement your own RNG by adhering to the `RngCore` and `CryptoRng` traits.

### Example Usage

```rust
use wsts::util::create_rng;
use wsts::v1::Signer;

// Initialize your RNG
let mut rng = create_rng();

// Create a signer
let signer = Signer::new(id, key_ids, N, T, &mut rng);
```

Ensure that you pass the RNG to all functions that require randomness.