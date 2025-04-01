// ignore_for_file: non_constant_identifier_names

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:coinlib/coinlib.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:test/test.dart';

import 'package:silent_payments/silent_payments.dart';
import 'test_utils.dart';

void main() async {
  await loadCoinlib();

  final testVectors = json.decode(
    File('test/data/send_and_receive_test_vectors.json').readAsStringSync(),
  );

  for (final vector in testVectors) {
    test(vector['comment'], () {
      // print('\x1B[36mSending:\x1B[0m');

      for (final sendingTest in vector['sending']) {
        final given = sendingTest["given"];
        final expected = sendingTest["expected"];

        final vins = <VinInfo>[];

        for (final input in given["vin"]) {
          vins.add(
            VinInfo(
              outpoint: OutPoint.fromHex(input['txid'], input['vout']),
              scriptSig: hexToBytes(input['scriptSig']),
              txinwitness: WitnessInput(
                prevOut: OutPoint.fromHex(input['txid'], input['vout']),
                witness:
                    deserStringVector(
                          ByteData.sublistView(
                            hexToBytes(input['txinwitness']),
                          ),
                        )
                        .map(
                          (bd) => Uint8List.view(
                            bd.buffer,
                            bd.offsetInBytes,
                            bd.lengthInBytes,
                          ),
                        )
                        .toList(),
              ),
              prevOutScript: Script.decompile(
                hexToBytes(input["prevout"]["scriptPubKey"]["hex"]),
              ),
              privkey: ECPrivateKey.fromHex(input['private_key']),
            ),
          );
        }

        // print(bytesToHex(vins[0].outpoint.hash));
        // print(bytesToHex(Uint8List.fromList(vins[0].scriptSig)));
        // print(bytesToHex(vins[0].prevOutScript.compiled));
        // print(bytesToHex(vins[0].privkey!.data));

        // Convert the tuples to lists so they can be easily compared to the json list of lists from the given test vectors

        final inputPrivKeys = <(ECPrivateKey?, bool)>[];
        final inputPubKeys = <ECPublicKey>[];

        for (final vin in vins) {
          final pubkey = getPubKeyFromInput(vin);
          // print("pubkey from input: ${pubkey?.hex}");
          if (pubkey == null) continue;

          inputPrivKeys.add((vin.privkey, isP2TR(vin.prevOutScript.compiled)));
          inputPubKeys.add(pubkey);
        }

        // print(inputPubKeys.map((key) => key.hex));

        List<String> sendingOutputs = [];

        if (inputPubKeys.isNotEmpty) {
          final outpoints = vins.map((vin) => vin.outpoint).toList();
          final inputPrivateInfos =
              inputPrivKeys
                  .map((privkey) => ECPrivateInfo(privkey.$1!, privkey.$2))
                  .toList();
          final destinations =
              List<String>.from(given['recipients'])
                  .map(
                    (recipient) =>
                        SilentPaymentDestination.fromAddress(recipient, 0),
                  )
                  .toList();

          final builder = SilentPaymentBuilder(
            outpoints: outpoints,
            publicKeys: inputPubKeys,
          );
          final outputMap = builder.createOutputs(
            inputPrivateInfos,
            destinations,
          );

          sendingOutputs =
              outputMap.values
                  .expand(
                    (outputs) => outputs.map((o) => bytesToHex(o.address.data)),
                  )
                  .toList();

          // Note: order doesn't matter for creating/finding the outputs. However, different orderings of the recipient addresses
          // will produce different generated outputs if sending to multiple silent payment addresses belonging to the
          // same sender but with different labels. Because of this, expected["outputs"] contains all possible valid output sets,
          // based on all possible permutations of recipient address orderings. Must match exactly one of the possible output sets.
          expect(
            (expected['outputs'] as List).any((lst) {
              final expectedSet = Set<String>.from(List<String>.from(lst));
              final actualSet = Set<String>.from(sendingOutputs);

              // print("Expected: $expectedSet");
              // print("Actual:   $actualSet");

              return expectedSet.length == actualSet.length &&
                  expectedSet.containsAll(
                    actualSet,
                  ); // TODO: I don't think this is right
            }),
            isTrue,
            reason: 'Sending test failed',
          );
        } else {
          expect(sendingOutputs, isEmpty, reason: 'Sending test failed');
          expect(
            expected['outputs'][0],
            isEmpty,
            reason: 'Expected output set should be empty',
          );
        }
      }

      // print('\x1B[36mReceiving:\x1B[0m');

      // Test receiving
      final msg = sha256.convert(utf8.encode("message")).bytes;
      final aux = sha256.convert(utf8.encode("random auxiliary data")).bytes;

      for (final receivingTest in vector['receiving']) {
        List<OutPoint> vinOutpoints = [];
        List<ECPublicKey> inputPubKeys = [];

        final given = receivingTest["given"];
        final expected = receivingTest["expected"];

        // TODO: decide if/when/where to convert the outputs to ECPublicKeys
        // final outputsToCheck = List<String>.from(given['outputs']);

        final outputsToCheck =
            List<String>.from(given['outputs'])
                .map((p) {
                  try {
                    return ECPublicKey.fromXOnlyHex(p);
                  } catch (_) {
                    return null;
                  }
                })
                .whereType<ECPublicKey>()
                .toList();

        // print('outputsToCheck: ${outputsToCheck.map((pubkey) => pubkey.hex)}');

        // not storing the List<VinInfo> this time
        for (final input in given["vin"]) {
          final vin = VinInfo(
            outpoint: OutPoint.fromHex(input['txid'], input['vout']),
            scriptSig: hexToBytes(input['scriptSig']),
            txinwitness: WitnessInput(
              prevOut: OutPoint.fromHex(input['txid'], input['vout']),
              witness:
                  deserStringVector(
                        ByteData.sublistView(hexToBytes(input['txinwitness'])),
                      )
                      .map(
                        (bd) => Uint8List.view(
                          bd.buffer,
                          bd.offsetInBytes,
                          bd.lengthInBytes,
                        ),
                      )
                      .toList(),
            ),
            prevOutScript: Script.decompile(
              hexToBytes(input["prevout"]["scriptPubKey"]["hex"]),
            ),
          );

          vinOutpoints.add(vin.outpoint);

          final pubkey = getPubKeyFromInput(vin);
          // print("pubkey from input: ${pubkey?.hex}");
          if (pubkey == null) continue;
          inputPubKeys.add(pubkey);
        }

        // Check that the given inputs for the receiving test match what was generated during the sending test
        final List<SilentPaymentAddress> receivingAddresses = [];

        final silentPaymentOwner = SilentPaymentOwner.fromPrivateKeys(
          b_scan: ECPrivateKey.fromHex(given["key_material"]["scan_priv_key"]),
          b_spend: ECPrivateKey.fromHex(
            given["key_material"]["spend_priv_key"],
          ),
        );

        // Add change address
        receivingAddresses.add(silentPaymentOwner.address);

        // G , needed for generating the labels "database"
        final G = ECPublicKey(ECCurve_secp256k1().G.getEncoded());

        Map<String, String>? preComputedLabels;

        for (var label in given['labels']) {
          receivingAddresses.add(silentPaymentOwner.toLabeledAddress(label));
          final generatedLabel = silentPaymentOwner.generateLabel(label);

          preComputedLabels ??= {};
          preComputedLabels[bytesToHex(
            tweakMulPublic(G, generatedLabel),
          )] = bytesToHex(generatedLabel);
        }
        // print('preComputedLabels: $preComputedLabels');

        for (var address in expected['addresses']) {
          expect(
            receivingAddresses.indexWhere(
              (sp) => sp.toString() == address.toString(),
            ),
            isNot(-1),
          );
        }

        // Check that the silent payment addresses match for the given BIP32 seed and labels dictionary
        assert(
          receivingAddresses.toString() == expected['addresses'].toString(),
          "Receiving addresses don't match",
        );

        if (inputPubKeys.isNotEmpty) {
          final spb = SilentPaymentBuilder(
            outpoints: vinOutpoints,
            publicKeys: inputPubKeys,
          );

          final addToWallet = spb.scanOutputs(
            silentPaymentOwner,
            outputsToCheck
                .map((o) => Output.fromScriptBytes(BigInt.zero, o.data))
                .toList(),
            precomputedLabels: preComputedLabels,
          );

          final expectedDestinations = expected['outputs'];
          final normalizedOutputs = <String>{};

          // print('Expected number of outputs: ${expectedDestinations.length}');
          // print('Actual number of outputs:   ${addToWallet.length}');

          // Check that the private key is correct for the found output public key
          for (int i = 0; i < expectedDestinations.length; i++) {
            // print('i=$i');

            final output = addToWallet.entries.elementAt(
              expectedDestinations.length - 1 - i,
            );
            final pubkey = output.key;
            // final expectedPubkey = expectedDestinations[i]["pub_key"];
            // expect(pubkey.substring(2), expectedPubkey);

            final privKeyTweak = output.value.tweak;
            // final expectedPrivKeyTweak =
            //     expectedDestinations[i]["priv_key_tweak"];
            // expect(privKeyTweak, expectedPrivKeyTweak);

            var fullPrivateKey =
                silentPaymentOwner.b_spend
                    .tweak(hexToBytes(privKeyTweak))!
                    .xonly;

            // TODO: I think '.xonly' handles this
            // if (!fullPrivateKey!.pubkey.yIsEven) {
            //   fullPrivateKey = negatePrivkey(fullPrivateKey);
            // }

            // final hash = bytesToHex(Uint8List.fromList(msg));
            // final privKey = bytesToHex(Uint8List.fromList(fullPrivateKey.data));
            // final extraEntropy = bytesToHex(Uint8List.fromList(aux));

            // print('msg    (${msg.length}): $hash');
            // print('priv   (${fullPrivateKey.data.length}): $privKey');
            // print('aux    (${aux.length}): $extraEntropy');

            // Sign the message with schnorr
            final signature = signSchnorr(
              Uint8List.fromList(msg),
              fullPrivateKey.data,
              Uint8List.fromList(aux),
            );

            // print('signature: ${bytesToHex(Uint8List.fromList(signature))}');

            // Verify the message is correct
            // expect(
            //   secp256k1.schnorrVerify(
            //     signature,
            //     Uint8List.fromList(msg),
            //     ECPublicKey.fromHex(pubkey).x,
            //   ),
            //   true,
            // );

            // ✅ Build normalized map for comparison
            final outputMap = {
              "pub_key": ECPublicKey.fromHex(pubkey).xhex,
              "priv_key_tweak": privKeyTweak,
              "signature": bytesToHex(Uint8List.fromList(signature)),
            };

            // ✅ Sort keys for consistent string representation
            final sortedMap = Map.fromEntries(
              outputMap.entries.toList()
                ..sort((a, b) => a.key.compareTo(b.key)),
            );

            normalizedOutputs.add(json.encode(sortedMap));
          }

          final expectedList = List<Map<String, dynamic>>.from(
            expected["outputs"],
          );
          final expectedSet =
              expectedList.map((m) {
                final sorted = Map.fromEntries(
                  m.entries.toList()..sort((a, b) => a.key.compareTo(b.key)),
                );
                return json.encode(sorted);
              }).toSet();

          expect(normalizedOutputs, expectedSet);
        }
      }
    });
  }
}
