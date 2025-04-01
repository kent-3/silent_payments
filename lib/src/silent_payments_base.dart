// ignore_for_file: constant_identifier_names
// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';
import 'package:coinlib/coinlib.dart';
import 'package:pointycastle/ecc/api.dart' show ECPoint;
import 'package:silent_payments/src/utils.dart';
import 'package:silent_payments/src/bech32m.dart';

// Derivation paths
const _SILENT_PAYMENTS_SCAN = "m/352'/0'/0'/1'/0";
const _SILENT_PAYMENTS_SPEND = "m/352'/0'/0'/0'/0";

// =====================================================================
// Address Classes
// =====================================================================

/// Base class for all Silent Payment addresses
class SilentPaymentAddress {
  static RegExp get regex => RegExp(r'(tsp|sp|sprt)1[0-9a-zA-Z]{113}');

  final ECPublicKey B_scan;
  final ECPublicKey B_spend;
  final int version;

  SilentPaymentAddress({
    required this.B_scan,
    required this.B_spend,
    this.version = 0,
  }) {
    if (version != 0) {
      throw Exception("Only version 0 is currently supported");
    }
  }

  /// Create a SilentPaymentAddress from a bech32m encoded string
  factory SilentPaymentAddress.fromAddress(String address) {
    final decoded = Bech32mCodec.decodeSilentPayment(address);

    return SilentPaymentAddress(
      B_scan: ECPublicKey(decoded['B_scan']),
      B_spend: ECPublicKey(decoded['B_spend']),
      version: decoded['version'],
    );
  }

  /// Convert address to bech32m encoded string
  @override
  String toString({String? network}) {
    final prefix = switch (network) {
      'BitcoinNetwork.testnet' => 'tsp',
      'BitcoinNetwork.regtest' => 'sprt',
      _ => 'sp',
    };

    return Bech32mCodec.encodeSilentPayment(
      hrp: prefix,
      version: version,
      B_scan: B_scan.data,
      B_spend: B_spend.data,
    );
  }
}

/// A Silent Payment address with associated private keys
class SilentPaymentOwner {
  final ECPrivateKey b_scan;
  final ECPrivateKey b_spend;
  final SilentPaymentAddress address;

  SilentPaymentOwner({
    required this.b_scan,
    required this.b_spend,
    required this.address,
  });

  /// Create a SilentPaymentOwner from private keys
  factory SilentPaymentOwner.fromPrivateKeys({
    required ECPrivateKey b_scan,
    required ECPrivateKey b_spend,
    int version = 0,
  }) {
    return SilentPaymentOwner(
      b_scan: b_scan,
      b_spend: b_spend,
      address: SilentPaymentAddress(
        B_scan: b_scan.pubkey,
        B_spend: b_spend.pubkey,
        version: version,
      ),
    );
  }

  /// Create a SilentPaymentOwner from a BIP32 HD wallet
  factory SilentPaymentOwner.fromBip32(HDPrivateKey bip32, {int version = 0}) {
    final scanDerivation = bip32.derivePath(_SILENT_PAYMENTS_SCAN);
    final spendDerivation = bip32.derivePath(_SILENT_PAYMENTS_SPEND);

    return SilentPaymentOwner.fromPrivateKeys(
      b_scan: scanDerivation.privateKey,
      b_spend: spendDerivation.privateKey,
      version: version,
    );
  }

  /// Create a SilentPaymentOwner from a seed
  factory SilentPaymentOwner.fromSeed(
    Uint8List seed, {
    String? network,
    int version = 0,
  }) {
    return SilentPaymentOwner.fromBip32(
      HDPrivateKey.fromSeed(seed),
      version: version,
    );
  }

  /// Generate a labeled address by tweaking the spend key
  Uint8List generateLabel(int label) {
    return taggedHash([...b_scan.data, ...serUint32(label)], "BIP0352/Label");
  }

  /// Create a labeled address
  SilentPaymentAddress toLabeledAddress(int label) {
    final B_m = address.B_spend.tweak(generateLabel(label))!;

    return SilentPaymentAddress(
      B_scan: address.B_scan,
      B_spend: B_m,
      version: address.version,
    );
  }

  /// Export to JSON representation
  Map<String, dynamic> toJson() {
    return {
      'version': address.version,
      'scan_key': address.B_scan.hex,
      'spend_key': address.B_spend.hex,
      'scan_private_key': bytesToHex(b_scan.data),
      'spend_private_key': bytesToHex(b_spend.data),
    };
  }

  /// Import from JSON representation
  static SilentPaymentOwner fromJson(Map<String, dynamic> json) {
    return SilentPaymentOwner(
      b_scan: ECPrivateKey(hexToBytes(json['scan_private_key'])),
      b_spend: ECPrivateKey(hexToBytes(json['spend_private_key'])),
      address: SilentPaymentAddress(
        B_scan: ECPublicKey.fromHex(json['scan_key']),
        B_spend: ECPublicKey.fromHex(json['spend_key']),
        version: json['version'],
      ),
    );
  }

  /// Get address string
  @override
  String toString({String? network}) => address.toString(network: network);
}

/// A destination for silent payments with amount
class SilentPaymentDestination {
  final SilentPaymentAddress address;
  final int amount;

  SilentPaymentDestination({required this.address, required this.amount});

  factory SilentPaymentDestination.fromAddress(String address, int amount) {
    return SilentPaymentDestination(
      address: SilentPaymentAddress.fromAddress(address),
      amount: amount,
    );
  }

  ECPublicKey get B_scan => address.B_scan;
  ECPublicKey get B_spend => address.B_spend;

  @override
  String toString() => address.toString();
}

// =====================================================================
// Payment Result Classes
// =====================================================================

/// A silent payment output for sending
class SilentPaymentOutput {
  final P2TRAddress address;
  final int amount;

  SilentPaymentOutput(this.address, this.amount);
}

/// A silent payment output for scanning/receiving
class SilentPaymentScanningOutput {
  final SilentPaymentOutput output;
  final String tweak;
  final String? label;

  SilentPaymentScanningOutput({
    required this.output,
    required this.tweak,
    this.label,
  });
}

/// Information about a private key in an input
class ECPrivateInfo {
  final ECPrivateKey privkey;
  final bool isTaproot;

  /// If `needsTweaking` is true, this key is assumed to be an internal Taproot key.
  /// It will be tweaked using taggedHash(pubkey_x, "TapTweak") before use.
  /// Otherwise, it is assumed to be already tweaked and ready to use.
  final bool needsTweaking;

  ECPrivateInfo(this.privkey, this.isTaproot, {this.needsTweaking = false});
}

// =====================================================================
// Payment Builder Class
// =====================================================================

class SilentPaymentBuilder {
  final List<OutPoint> outpoints;
  final List<ECPublicKey>? publicKeys;
  final String hrp;
  String? receiverTweak;
  ECPublicKey? _A_sum;
  Uint8List? _inputHash;

  SilentPaymentBuilder({
    required this.outpoints,
    this.publicKeys,
    this.receiverTweak,
    this.hrp = 'bc',
  }) {
    assert(
      receiverTweak != null || publicKeys != null,
      'Must provide either receiverTweak or publicKeys.',
    );

    if (receiverTweak == null && publicKeys != null) {
      _getAsum();
      _getInputHash();
    }
  }

  void _getAsum() {
    if (publicKeys == null || publicKeys!.isEmpty) return;

    final head = publicKeys!.first;
    final tail = publicKeys!.sublist(1);

    final ECPoint sum = tail.fold<ECPoint>(
      decodePoint(head),
      (acc, item) => (acc + decodePoint(item))!,
    );

    if (sum.isInfinity) {
      _A_sum = null;
      return;
    }

    _A_sum = ECPublicKey(sum.getEncoded());
  }

  void _getInputHash() {
    if (_A_sum == null) return;

    final sorted =
        outpoints.toList()
          ..sort((a, b) => compareBytes(a.toBytes(), b.toBytes()));

    final lowestOutpoint = sorted.first;

    _inputHash = taggedHash(
      Uint8List.fromList([...lowestOutpoint.toBytes(), ..._A_sum!.data]),
      "BIP0352/Inputs",
    );
  }

  /// Create outputs for the given destinations
  Map<String, List<SilentPaymentOutput>> createOutputs(
    List<ECPrivateInfo> inputPrivKeyInfos,
    List<SilentPaymentDestination> destinations,
  ) {
    ECPrivateKey? a_sum;

    // Calculate the sum of private keys
    for (final info in inputPrivKeyInfos) {
      var k = info.privkey;
      final isTaproot = info.isTaproot;

      if (isTaproot) {
        final pubkey = k.pubkey;
        final isOdd =
            decodePoint(pubkey).y!.toBigInteger()! % BigInt.two != BigInt.zero;

        if (isOdd) {
          k = k.negate();
        }

        if (info.needsTweaking) {
          k = k.tweak(taggedHash(k.pubkey.x, "TapTweak"))!;
        }
      }

      if (a_sum == null) {
        a_sum = k;
      } else {
        a_sum = a_sum.tweak(k.data);
      }
    }

    _A_sum = a_sum?.pubkey;
    _getInputHash();

    if (_A_sum == null || _inputHash == null) {
      return {};
    }

    // Group destinations by scan key for efficiency
    Map<String, Map<String, List<SilentPaymentDestination>>> destinationGroups =
        {};

    for (final destination in destinations) {
      final scanKey = destination.B_scan;
      final scanHex = scanKey.hex;

      if (destinationGroups.containsKey(scanHex)) {
        // Current key already in destinationGroups, simply add the new destination
        // with the already calculated shared secret
        final group = destinationGroups[scanHex]!;
        final sharedSecret = group.keys.first;
        final recipients = group.values.first;

        destinationGroups[scanHex] = {
          sharedSecret: [...recipients, destination],
        };
      } else {
        final senderPartialSecret = tweakMulPrivate(a_sum!.data, _inputHash!);
        final sharedSecret = tweakMulPublic(scanKey, senderPartialSecret);

        destinationGroups[scanHex] = {
          bytesToHex(sharedSecret): [destination],
        };
      }
    }

    // Create outputs for each destination
    Map<String, List<SilentPaymentOutput>> result = {};

    for (final group in destinationGroups.entries) {
      final sharedSecret = group.value.keys.first;
      final groupDestinations = group.value.values.first;

      int outputIndex = 0;
      for (final destination in groupDestinations) {
        final indexBytes = ByteData(4)..setUint32(0, outputIndex);

        final outputTweak = taggedHash([
          ...hexToBytes(sharedSecret),
          ...indexBytes.buffer.asUint8List(),
        ], "BIP0352/SharedSecret");

        final tweakedKey = destination.B_spend.tweak(outputTweak)!;
        final output = SilentPaymentOutput(
          P2TRAddress.fromTweakedKey(tweakedKey, hrp: hrp),
          destination.amount,
        );

        if (result.containsKey(destination.toString())) {
          result[destination.toString()]!.add(output);
        } else {
          result[destination.toString()] = [output];
        }

        outputIndex++;
      }
    }

    return result;
  }

  /// Scan outputs for those belonging to the given owner
  Map<String, SilentPaymentScanningOutput> scanOutputs(
    SilentPaymentOwner owner,
    List<Output> outputsToCheck, {
    Map<String, String>? precomputedLabels,
  }) {
    if (_A_sum == null || _inputHash == null) {
      return {};
    }

    final tweakDataForRecipient =
        receiverTweak != null
            ? ECPublicKey.fromHex(receiverTweak!)
            : ECPublicKey(tweakMulPublic(_A_sum!, _inputHash!));

    final sharedSecret = ECPublicKey(
      tweakMulPublic(tweakDataForRecipient, owner.b_scan.data),
    );

    final matches = <String, SilentPaymentScanningOutput>{};
    var outputIndex = 0;

    while (outputsToCheck.isNotEmpty) {
      final indexBytes = ByteData(4)..setUint32(0, outputIndex);

      final outputTweak = taggedHash([
        ...sharedSecret.data,
        ...indexBytes.buffer.asUint8List(),
      ], "BIP0352/SharedSecret");

      final expectedKey = owner.address.B_spend.tweak(outputTweak);

      bool foundMatch = false;

      for (var i = 0; i < outputsToCheck.length; i++) {
        final output = outputsToCheck[i].scriptPubKey;
        final outputPubkey = bytesToHex(output);
        final outputAmount = outputsToCheck[i].value.toInt();

        // Check for exact match
        if (bytesEqual(output.sublist(1), expectedKey!.data.sublist(1))) {
          matches[outputPubkey] = SilentPaymentScanningOutput(
            output: SilentPaymentOutput(
              P2TRAddress.fromTweakedKey(expectedKey, hrp: hrp),
              outputAmount,
            ),
            tweak: bytesToHex(outputTweak),
          );
          outputsToCheck.removeAt(i);
          outputIndex++;
          foundMatch = true;
          break;
        }

        // Check for labeled outputs if labels provided
        if (precomputedLabels != null && precomputedLabels.isNotEmpty) {
          var labelDiff = ECPublicKey(output).add(expectedKey.negate());
          var labelKey = precomputedLabels[labelDiff.hex];

          if (labelKey == null) {
            labelDiff = ECPublicKey(output).negate().add(expectedKey.negate());
            labelKey = precomputedLabels[labelDiff.hex];
          }

          if (labelKey != null) {
            final labeledKey = expectedKey.tweak(hexToBytes(labelKey));

            matches[outputPubkey] = SilentPaymentScanningOutput(
              output: SilentPaymentOutput(
                P2TRAddress.fromTweakedKey(labeledKey!, hrp: hrp),
                outputAmount,
              ),
              tweak: bytesToHex(
                ECPrivateKey(outputTweak).tweak(hexToBytes(labelKey))!.data,
              ),
              label: labelKey,
            );

            outputsToCheck.removeAt(i);
            outputIndex++;
            foundMatch = true;
            break;
          }
        }
      }

      if (!foundMatch) break;
    }

    return matches;
  }
}
