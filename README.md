<!--
This README describes the package. If you publish this package to pub.dev,
this README's contents appear on the landing page for your package.

For information about how to write a good package README, see the guide for
[writing package pages](https://dart.dev/tools/pub/writing-package-pages).

For general information about developing packages, see the Dart guide for
[creating packages](https://dart.dev/guides/libraries/create-packages)
and the Flutter guide for
[developing packages and plugins](https://flutter.dev/to/develop-packages).
-->

A pure Dart library for working with [BIP-352: Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki), enabling private Bitcoin payments without revealing the recipient's address on-chain.

## Features

- Generate Silent Payment addresses
- Derive unique payment outputs for senders using a shared secret
- Scan UTXOs for received payments
- Compatible with [test vectors](https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json) from BIP-352
- Minimal dependencies

## Getting started

TODO: List prerequisites and provide or point to information on how to
start using the package.

## Usage

TODO: Include short and useful examples for package users. Add longer examples
to `/example` folder.

```dart
const like = 'sample';
```

## Additional information

TODO: Tell users more about the package: where to find more information, how to
contribute to the package, how to file issues, what response they can expect
from the package authors, and more.
