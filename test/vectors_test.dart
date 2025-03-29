import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:test/test.dart';
// import 'package:convert/convert.dart';
import 'package:silent_payments/silent_payments.dart';
import 'package:coinlib/coinlib.dart';
// import 'package:convert/convert.dart/';

void main() async {
  await loadCoinlib();

  final testVectors = json.decode(
    File('test/data/send_and_receive_test_vectors.json').readAsStringSync(),
  );

  for (final vector in testVectors) {
    test(vector['comment'], () {
      // print(vector['comment']);
      for (final sending_test in vector['sending']) {
        final given = sending_test["given"];
        final expected = sending_test["expected"];

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
    });
  }
}
