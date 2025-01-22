# WSTS

[![ci](https://github.com/Trust-Machines/wsts/actions/workflows/ci.yml/badge.svg)](https://github.com/Trust-Machines/wsts/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/wsts.svg)](https://crates.io/crates/wsts)

[```WSTS```](https://tmurl.net/wsts) is a system for making ```Weighted Schnorr Threshold Signatures```, aka ```WileyProofs```.  It allows a group of ```signers```, each of whom controls a set of ```keys```, to make a valid ```Schnorr``` signature, as long as ```T``` (the ```threshold```) of them complete the protocol honestly.  While there are many other threshold signature schemes, ```WSTS``` has several features which make it particularly useful in a cryptocurrency context.

First, it is optimized for a small number of rounds in the common case where there are no byzantine actors present.  Since the protocol allows detection any bad actors in the system, it makes sense to optimize for the case where there are none.  Such byzantine actors can be sanctioned in a way that severely disincentivezes attempts to subvert the protocol.

Second, in contrast to typical ```multisig``` protocols, ```WSTS``` produces a single aggregate signature which is indistinguisable from a standard ```Schnorr``` signature. Crucially, this signature can be verified the same way as any ```Schnorr``` signature.  And since the signature is aggregated, it does not take any more space on chain than any other standard signature, and linearly less than traditional ```multisig``` signatures.

Finally, ```WSTS``` is designed to build aggregate threshold signatures which are weighted, i.e. not all signers control the same number of keys.  The ```threshold``` is a function of keys, so a set of signers meets the ```threshold``` if and only if the sum of the number of keys they control equals or exceeds the ```threshold```.

## Background
```WSTS``` is based on [```FROST```](https://eprint.iacr.org/2020/852.pdf), i.e. ```Flexible Round-Optimized Schnorr Threshold``` signatures.  ```FROST``` provides a system where a number of ```parties```, each of which controls a single ```key```, can form an aggregate group signing key, after which a ```threshold``` number of them can cooperate to form a valid ```Schnorr``` signature.

## Variants
This crate provides a simple implementation of ```WSTS``` in the ```v1``` module, which is an extension of ```FROST``` where each ```signer``` controls a set of ```parties```, each of which controls a single ```key```.

This crate also contains a more complex version of ```WSTS``` optimized for the weighted threshold scenario in the ```v2``` module.  Like vanilla ```FROST```, ```v2``` keeps a single polynomial and nonce for each ```Party```, but allows each ```Party``` to control multiple keys.  This allows for order-of-magnitude reductions in data size and number of messages for the distributed key generation (```DKG```) and signing parts of the protocol.

## p256k1
This crate uses the Bitcoin ```secp256k1``` curve.  But since the C ```libsecp256k1``` library only provides high level interfaces for operations used by Bitcoin, it was necessary to directly expose the scalars and curve points to allow arbitrary mathematical operations outside of sign/verify.  So we provide a wrapper crate around ```libsecp256k1``` which wraps the internal interfaces to scalars and points.  We call this crate [```p256k1```](https://crates.io/crates/p256k1), to denote that it is not only the same curve as ```secp256k1```, but also exposes the curve directly.


## Documentation

- [wsts crate docs in GitHub](https://trust-machines.github.io/wsts/wsts)
- [WSTS Paper](https://trust-machines.github.io/wsts/wsts.pdf)

## Copyright and License

Copyright 2022-2024, Nassau Machines Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

 [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
