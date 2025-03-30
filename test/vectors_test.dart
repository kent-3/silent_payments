// ignore_for_file: non_constant_identifier_names

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:coinlib/coinlib.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:test/test.dart';
import 'package:coinlib/src/secp256k1/secp256k1.dart';

import 'package:silent_payments/silent_payments.dart';

void main() async {
  await loadCoinlib();

  final testVectors = json.decode(
    File('test/data/send_and_receive_test_vectors.json').readAsStringSync(),
  );

  for (final vector in testVectors) {
    test(vector['comment'], () {
      print('\x1B[36mSending:\x1B[0m');

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
          print("pubkey from input: ${pubkey?.hex}");
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
            vinOutpoints: outpoints,
            pubkeys: inputPubKeys,
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

              print("Expected: $expectedSet");
              print("Actual:   $actualSet");

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

      print('\x1B[36mReceiving:\x1B[0m');

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

        print('outputsToCheck: ${outputsToCheck.map((pubkey) => pubkey.hex)}');

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
          print("pubkey from input: ${pubkey?.hex}");
          if (pubkey == null) continue;
          inputPubKeys.add(pubkey);
        }

        // Check that the given inputs for the receiving test match what was generated during the sending test
        final List<SilentPaymentOwner> receivingAddresses = [];

        final silentPaymentOwner = SilentPaymentOwner.fromPrivateKeys(
          b_scan: ECPrivateKey.fromHex(given["key_material"]["scan_priv_key"]),
          b_spend: ECPrivateKey.fromHex(
            given["key_material"]["spend_priv_key"],
          ),
        );

        // Add change address
        receivingAddresses.add(silentPaymentOwner);

        // G , needed for generating the labels "database"
        final G = ECPublicKey(ECCurve_secp256k1().G.getEncoded());

        Map<String, String>? preComputedLabels;

        for (var label in given['labels']) {
          receivingAddresses.add(
            silentPaymentOwner.toLabeledSilentPaymentAddress(label),
          );
          final generatedLabel = silentPaymentOwner.generateLabel(label);

          preComputedLabels ??= {};
          preComputedLabels[bytesToHex(
            tweakMulPublic(G, generatedLabel),
          )] = bytesToHex(generatedLabel);
        }

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

        final addToWallet = [];

        if (inputPubKeys.isNotEmpty) {
          final spb = SilentPaymentBuilder(
            pubkeys: inputPubKeys,
            vinOutpoints: vinOutpoints,
          );

          final addToWallet = spb.scanOutputs(
            silentPaymentOwner.b_scan,
            silentPaymentOwner.B_spend,
            outputsToCheck
                .map((o) => Output.fromScriptBytes(BigInt.zero, o.data))
                .toList(),
            precomputedLabels: preComputedLabels,
          );

          final expectedDestinations = expected['outputs'];

          // Check that the private key is correct for the found output public key
          for (int i = 0; i < expectedDestinations.length; i++) {
            final output = addToWallet.entries.elementAt(i);
            final pubkey = output.key;
            final expectedPubkey = expectedDestinations[i]["pub_key"];
            expect(pubkey.substring(2), expectedPubkey);

            final privKeyTweak = output.value.tweak;
            final expectedPrivKeyTweak =
                expectedDestinations[i]["priv_key_tweak"];
            expect(privKeyTweak, expectedPrivKeyTweak);

            var fullPrivateKey =
                silentPaymentOwner.b_spend
                    .tweak(hexToBytes(privKeyTweak))
                    ?.xonly;

            // TODO: I think '.xonly' handles this
            // if (!fullPrivateKey!.pubkey.yIsEven) {
            //   fullPrivateKey = negatePrivkey(fullPrivateKey);
            // }

            // Sign the message with schnorr
            final signature = secp256k1.schnorrSign(
              Uint8List.fromList(msg),
              fullPrivateKey!.data,
              Uint8List.fromList(aux),
            );

            // Verify the message is correct
            expect(
              secp256k1.schnorrVerify(
                signature,
                Uint8List.fromList(msg),
                ECPublicKey.fromHex(pubkey).x,
              ),
              true,
            );

            // Verify the signature is correct
            expect(
              bytesToHex(Uint8List.fromList(signature)),
              expectedDestinations[i]["signature"],
            );

            i++;
          }
        }

        // if (len(input_pub_keys) > 0):
        //     A_sum = reduce(lambda x, y: x + y, input_pub_keys)
        //     if A_sum.get_bytes() is None:
        //         # Input pubkeys sum is point at infinity -> skip tx
        //         assert expected["outputs"] == []
        //         continue
        //     input_hash = get_input_hash([vin.outpoint for vin in vins], A_sum)
        //     pre_computed_labels = {
        //         (generate_label(b_scan, label) * G).get_bytes(False).hex(): generate_label(b_scan, label).hex()
        //         for label in given["labels"]
        //     }
        //     add_to_wallet = scanning(
        //         b_scan=b_scan,
        //         B_spend=B_spend,
        //         A_sum=A_sum,
        //         input_hash=input_hash,
        //         outputs_to_check=outputs_to_check,
        //         labels=pre_computed_labels,
        //     )
      }
    });
  }
}
