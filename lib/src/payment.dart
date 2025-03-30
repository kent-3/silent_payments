// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';
import 'package:coinlib/coinlib.dart';
import 'package:silent_payments/src/utils.dart';
import 'package:silent_payments/src/address.dart';
import 'package:pointycastle/ecc/api.dart' show ECPoint;

class SilentPaymentOutput {
  final P2TRAddress address;
  final int amount;

  SilentPaymentOutput(this.address, this.amount);
}

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

class ECPrivateInfo {
  final ECPrivateKey privkey;
  final bool isTaproot;
  final bool tweak;

  ECPrivateInfo(this.privkey, this.isTaproot, {this.tweak = false});
}

class SilentPaymentBuilder {
  final List<OutPoint> vinOutpoints;
  final List<ECPublicKey>? pubkeys;
  ECPublicKey? A_sum;
  Uint8List? inputHash;
  String? receiverTweak;

  SilentPaymentBuilder({
    required this.vinOutpoints,
    this.pubkeys,
    this.receiverTweak,
  }) {
    if (receiverTweak == null && pubkeys != null) {
      _getAsum();
      _getInputHash();
    }
  }

  // void _getAsum() {
  //   final head = pubkeys!.first;
  //   final tail = pubkeys!.sublist(1);
  //
  //   A_sum = tail.fold<ECPublicKey>(
  //     head,
  //     (acc, item) =>
  //         ECPublicKey((decodePoint(acc) + decodePoint(item))!.getEncoded()),
  //   );
  // }

  void _getAsum() {
    final head = pubkeys!.first;
    final tail = pubkeys!.sublist(1);

    final ECPoint sum = tail.fold<ECPoint>(
      decodePoint(head),
      (acc, item) => (acc + decodePoint(item))!,
    );

    if (sum.isInfinity) {
      A_sum = null;
      return;
    }

    A_sum = ECPublicKey(sum.getEncoded());
  }

  void _getInputHash() {
    if (A_sum == null) return; // graceful early exit

    final sorted =
        vinOutpoints.toList()
          ..sort((a, b) => compareBytes(a.toBytes(), b.toBytes()));

    final lowestOutpoint = sorted.first;

    inputHash = taggedHash(
      Uint8List.fromList([...lowestOutpoint.toBytes(), ...A_sum!.data]),
      "BIP0352/Inputs",
    );
  }

  Map<String, List<SilentPaymentOutput>> createOutputs(
    List<ECPrivateInfo> inputPrivKeyInfos,
    List<SilentPaymentDestination> silentPaymentDestinations,
  ) {
    ECPrivateKey? a_sum;

    for (final info in inputPrivKeyInfos) {
      var k = info.privkey;
      final isTaproot = info.isTaproot;

      if (isTaproot) {
        final pubkey = k.pubkey;
        final isOdd =
            decodePoint(pubkey).y!.toBigInteger()! % BigInt.two != BigInt.zero;

        if (isOdd) {
          k = negatePrivkey(k);
        }

        if (info.tweak) {
          k = k.tweak(taggedHash(k.pubkey.x, "TapTweak"))!;
        }
      }

      if (a_sum == null) {
        a_sum = k;
      } else {
        a_sum = a_sum.tweak(k.data);
      }
    }

    A_sum = a_sum?.pubkey;
    _getInputHash();

    if (A_sum == null || inputHash == null) {
      return {};
    }

    Map<String, Map<String, List<SilentPaymentDestination>>>
    silentPaymentGroups = {};

    for (final silentPaymentDestination in silentPaymentDestinations) {
      final B_scan = silentPaymentDestination.B_scan;
      final scanPubkey = B_scan.hex;

      // print('A_sum: $A_sum');
      // print('B_scan: $scanPubkey');
      // print('B_m: ${silentPaymentDestination.B_spend.hex}');
      // print('inputHash: ${bytesToHex(inputHash!)}');

      if (silentPaymentGroups.containsKey(scanPubkey)) {
        // Current key already in silentPaymentGroups, simply add up the new destination
        // with the already calculated ecdhSharedSecret
        final group = silentPaymentGroups[scanPubkey]!;
        final ecdhSharedSecret = group.keys.first;
        final recipients = group.values.first;

        silentPaymentGroups[scanPubkey] = {
          ecdhSharedSecret: [...recipients, silentPaymentDestination],
        };
      } else {
        final senderPartialSecret = tweakMulPrivate(a_sum!.data, inputHash!);
        final ecdhSharedSecret = tweakMulPublic(B_scan, senderPartialSecret);

        // print('ecdhSharedSecret: ${bytesToHex(ecdhSharedSecret)}');
        // print('destination: $silentPaymentDestination');

        silentPaymentGroups[scanPubkey] = {
          bytesToHex(ecdhSharedSecret): [silentPaymentDestination],
        };
      }
    }

    Map<String, List<SilentPaymentOutput>> result = {};
    for (final group in silentPaymentGroups.entries) {
      final ecdhSharedSecret = group.value.keys.first;
      final destinations = group.value.values.first;

      int k = 0;
      for (final destination in destinations) {
        final kBytes = ByteData(4)..setUint32(0, k);

        final t_k = taggedHash([
          ...hexToBytes(ecdhSharedSecret),
          ...kBytes.buffer.asUint8List(),
        ], "BIP0352/SharedSecret");

        final P_mn = destination.B_spend.tweak(t_k)!;
        final resOutput = SilentPaymentOutput(
          P2TRAddress.fromTweakedKey(
            P_mn,
            hrp: 'bc',
          ), // TODO: allow for testnet
          destination.amount,
        );

        if (result.containsKey(destination.toString())) {
          result[destination.toString()]!.add(resOutput);
        } else {
          result[destination.toString()] = [resOutput];
        }

        k++;
      }
    }

    return result;
  }

  Map<String, SilentPaymentScanningOutput> scanOutputs(
    ECPrivateKey b_scan,
    ECPublicKey B_spend,
    List<Output> outputsToCheck, {
    Map<String, String>? precomputedLabels,
  }) {
    // TODO: is this the best place to handle this case?
    if (A_sum == null || inputHash == null) {
      return {};
    }

    final tweakDataForRecipient =
        receiverTweak != null
            ? ECPublicKey.fromHex(receiverTweak!)
            : ECPublicKey(tweakMulPublic(A_sum!, inputHash!));
    final ecdhSharedSecret = ECPublicKey(
      tweakMulPublic(tweakDataForRecipient, b_scan.data),
    );

    final matches = <String, SilentPaymentScanningOutput>{};
    var k = 0;

    do {
      final kBytes = ByteData(4)..setUint32(0, k);

      final t_k = taggedHash([
        ...ecdhSharedSecret.data,
        ...kBytes.buffer.asUint8List(),
      ], "BIP0352/SharedSecret");

      final P_k = B_spend.tweak(t_k);
      final length = outputsToCheck.length;

      for (var i = 0; i < length; i++) {
        final output = outputsToCheck[i].scriptPubKey;
        final outputPubkey = bytesToHex(output);
        final outputAmount = outputsToCheck[i].value.toInt();

        // NOTE: remove the key parity for byte comparison
        if (bytesEqual(output.sublist(1), P_k!.data.sublist(1))) {
          matches[outputPubkey] = SilentPaymentScanningOutput(
            output: SilentPaymentOutput(
              P2TRAddress.fromTweakedKey(P_k, hrp: 'bc'),
              outputAmount,
            ),
            tweak: bytesToHex(t_k),
          );
          outputsToCheck.removeAt(i);
          k++;
          break;
        }

        if (precomputedLabels != null && precomputedLabels.isNotEmpty) {
          var m_G_sub = addPubkeys(ECPublicKey(output), negatePubkey(P_k));
          var m_G = precomputedLabels[m_G_sub.hex];

          if (m_G == null) {
            print('output pubkey: ${ECPublicKey(output).hex}');
            print('P_k pubkey:    ${P_k.hex}');

            m_G_sub = addPubkeys(
              negatePubkey(ECPublicKey(output)),
              negatePubkey(P_k),
            );
            m_G = precomputedLabels[m_G_sub.hex];
          }

          if (m_G != null) {
            final P_km = P_k.tweak(hexToBytes(m_G));

            matches[outputPubkey] = SilentPaymentScanningOutput(
              output: SilentPaymentOutput(
                P2TRAddress.fromTweakedKey(P_km!, hrp: 'bc'),
                outputAmount,
              ),
              tweak: bytesToHex(ECPrivateKey(t_k).tweak(hexToBytes(m_G))!.data),
              label: m_G,
            );

            outputsToCheck.removeAt(i);
            k++;
            break;
          }
        }

        outputsToCheck.removeAt(i);

        if (i + 1 >= outputsToCheck.length) {
          break;
        }
      }
    } while (outputsToCheck.isNotEmpty);

    return matches;
  }
}

// TODO:
// BitcoinScriptOutput getScriptFromOutput(String pubkey, int amount) {
//   return BitcoinScriptOutput(
//     script: Script(script: [BitcoinOpCodeConst.OP_1, pubkey]),
//     value: BigInt.from(amount),
//   );
// }
