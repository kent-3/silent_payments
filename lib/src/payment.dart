// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';
import 'package:coinlib/coinlib.dart';
import 'package:silent_payments/src/utils.dart';
import 'package:silent_payments/src/address.dart';
import 'package:pointycastle/ecc/api.dart' show ECPoint;
import 'package:pointycastle/ecc/curves/secp256k1.dart' show ECCurve_secp256k1;

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

  ECPoint decodePoint(ECPublicKey pubkey) {
    final curve = ECCurve_secp256k1().curve;
    return curve.decodePoint(pubkey.data)!;
  }

  void _getAsum() {
    final head = pubkeys!.first;
    final tail = pubkeys!.sublist(1);

    A_sum = tail.fold<ECPublicKey>(
      head,
      (acc, item) =>
          ECPublicKey((decodePoint(acc) + decodePoint(item))!.getEncoded()),
    );
  }

  void _getInputHash() {
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

      // TODO: double check this (but I'm pretty sure it's OK)
      if (isTaproot && info.tweak) {
        k = k.tweak(taggedHash(k.pubkey.x, "TapTweak"))!;
      }

      if (a_sum == null) {
        a_sum = k;
      } else {
        a_sum = a_sum.tweak(k.data);
      }
    }

    A_sum = a_sum!.pubkey;
    _getInputHash();

    Map<String, Map<String, List<SilentPaymentDestination>>>
    silentPaymentGroups = {};

    for (final silentPaymentDestination in silentPaymentDestinations) {
      final B_scan = silentPaymentDestination.B_scan;
      final scanPubkey = B_scan.hex;

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
        final senderPartialSecret = tweakMul(a_sum.data, inputHash!);
        final ecdhSharedSecret = bytesToHex(
          tweakMul(B_scan.data, senderPartialSecret),
        );

        silentPaymentGroups[scanPubkey] = {
          ecdhSharedSecret: [silentPaymentDestination],
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
          ...ECPublicKey.fromHex(ecdhSharedSecret).data,
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

  //   Map<String, SilentPaymentScanningOutput> scanOutputs(
  //     ECPrivate b_scan,
  //     ECPublic B_spend,
  //     List<BitcoinScriptOutput> outputsToCheck, {
  //     Map<String, String>? precomputedLabels,
  //   }) {
  //     final tweakDataForRecipient =
  //         receiverTweak != null
  //             ? ECPublic.fromHex(receiverTweak!)
  //             : A_sum!.tweakMul(BigintUtils.fromBytes(inputHash!));
  //     final ecdhSharedSecret = tweakDataForRecipient.tweakMul(b_scan.toBigInt());
  //
  //     final matches = <String, SilentPaymentScanningOutput>{};
  //     var k = 0;
  //
  //     do {
  //       final t_k = taggedHash(
  //         BytesUtils.concatBytes([
  //           ecdhSharedSecret.toCompressedBytes(),
  //           BigintUtils.toBytes(BigInt.from(k), length: 4, order: Endian.big),
  //         ]),
  //         "BIP0352/SharedSecret",
  //       );
  //
  //       final P_k = B_spend.tweakAdd(BigintUtils.fromBytes(t_k));
  //       final length = outputsToCheck.length;
  //
  //       for (var i = 0; i < length; i++) {
  //         final output = outputsToCheck[i].script.toBytes().sublist(2);
  //         final outputPubkey = BytesUtils.toHexString(output);
  //         final outputAmount = outputsToCheck[i].value.toInt();
  //
  //         if ((BytesUtils.compareBytes(
  //               output,
  //               P_k.toCompressedBytes().sublist(1),
  //             ) ==
  //             0)) {
  //           matches[outputPubkey] = SilentPaymentScanningOutput(
  //             output: SilentPaymentOutput(
  //               P_k.toTaprootAddress(tweak: false),
  //               outputAmount,
  //             ),
  //             tweak: BytesUtils.toHexString(t_k),
  //           );
  //           outputsToCheck.removeAt(i);
  //           k++;
  //           break;
  //         }
  //
  //         if (precomputedLabels != null && precomputedLabels.isNotEmpty) {
  //           var m_G_sub = ECPublic.fromBytes(output).pubkeyAdd(P_k.negate());
  //           var m_G = precomputedLabels[m_G_sub.toHex()];
  //
  //           if (m_G == null) {
  //             m_G_sub = ECPublic.fromBytes(
  //               output,
  //             ).negate().pubkeyAdd(P_k.negate());
  //             m_G = precomputedLabels[m_G_sub.toHex()];
  //           }
  //
  //           if (m_G != null) {
  //             final P_km = P_k.tweakAdd(
  //               BigintUtils.fromBytes(BytesUtils.fromHexString(m_G)),
  //             );
  //
  //             matches[outputPubkey] = SilentPaymentScanningOutput(
  //               output: SilentPaymentOutput(
  //                 P_km.toTaprootAddress(tweak: false),
  //                 outputAmount,
  //               ),
  //               tweak:
  //                   ECPrivate.fromBytes(t_k)
  //                       .tweakAdd(
  //                         BigintUtils.fromBytes(BytesUtils.fromHexString(m_G)),
  //                       )
  //                       .toHex(),
  //               label: m_G,
  //             );
  //
  //             outputsToCheck.removeAt(i);
  //             k++;
  //             break;
  //           }
  //         }
  //
  //         outputsToCheck.removeAt(i);
  //
  //         if (i + 1 >= outputsToCheck.length) {
  //           break;
  //         }
  //       }
  //     } while (outputsToCheck.isNotEmpty);
  //
  //     return matches;
  //   }
  // }

  // BitcoinScriptOutput getScriptFromOutput(String pubkey, int amount) {
  //   return BitcoinScriptOutput(
  //     script: Script(script: [BitcoinOpCodeConst.OP_1, pubkey]),
  //     value: BigInt.from(amount),
  //   );
}
