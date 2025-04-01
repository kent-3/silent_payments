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
      _testSending(vector);
      _testReceiving(vector);
    });
  }
}

/// Test the sending portion of a test vector
void _testSending(Map<String, dynamic> vector) {
  for (final sendingTest in vector['sending']) {
    final given = sendingTest["given"];
    final expected = sendingTest["expected"];

    // Prepare input information
    final vins = _prepareVinInfoFromInputs(given["vin"]);
    final inputData = _extractInputKeysFromVins(vins);
    final inputPrivKeys = inputData.privKeys;
    final inputPubKeys = inputData.pubKeys;

    // Skip test if no input public keys are available
    if (inputPubKeys.isEmpty) {
      expect(expected['outputs'][0], isEmpty, 
          reason: 'Expected output set should be empty');
      continue;
    }

    // Prepare destination addresses
    final destinations = List<String>.from(given['recipients'])
        .map((recipient) => SilentPaymentDestination.fromAddress(recipient, 0))
        .toList();

    // Create outputs using the SilentPaymentBuilder
    final outpoints = vins.map((vin) => vin.outpoint).toList();
    final inputPrivateInfos = inputPrivKeys
        .map((privkey) => ECPrivateInfo(privkey.$1!, privkey.$2))
        .toList();

    final builder = SilentPaymentBuilder(
      outpoints: outpoints,
      publicKeys: inputPubKeys,
    );
    
    final outputMap = builder.createOutputs(inputPrivateInfos, destinations);
    final sendingOutputs = outputMap.values
        .expand((outputs) => outputs.map((o) => bytesToHex(o.address.data)))
        .toList();

    // Verify outputs against expected values
    // Note: The order doesn't matter for creating/finding outputs. Different orderings of recipient addresses
    // will produce different generated outputs if sending to multiple silent payment addresses belonging to the
    // same sender but with different labels. Because of this, expected["outputs"] contains all possible valid output sets.
    expect(
      (expected['outputs'] as List).any((lst) {
        final expectedSet = Set<String>.from(List<String>.from(lst));
        final actualSet = Set<String>.from(sendingOutputs);
        return expectedSet.length == actualSet.length &&
            expectedSet.containsAll(actualSet);
      }),
      isTrue,
      reason: 'Sending test failed',
    );
  }
}

/// Test the receiving portion of a test vector
void _testReceiving(Map<String, dynamic> vector) {
  // Create message and auxiliary data for signing
  final msg = sha256.convert(utf8.encode("message")).bytes;
  final aux = sha256.convert(utf8.encode("random auxiliary data")).bytes;

  for (final receivingTest in vector['receiving']) {
    final given = receivingTest["given"];
    final expected = receivingTest["expected"];

    // Prepare input information
    final vinInfo = _prepareVinInfoFromInputs(given["vin"]);
    final vinOutpoints = vinInfo.map((vin) => vin.outpoint).toList();
    
    // Extract public keys from inputs
    final inputPubKeys = vinInfo
        .map((vin) => getPubKeyFromInput(vin))
        .whereType<ECPublicKey>()
        .toList();

    // Parse outputs to check
    final outputsToCheck = List<String>.from(given['outputs'])
        .map((p) {
          try {
            return ECPublicKey.fromXOnlyHex(p);
          } catch (_) {
            return null;
          }
        })
        .whereType<ECPublicKey>()
        .toList();

    // Create SilentPaymentOwner from key material
    final silentPaymentOwner = SilentPaymentOwner.fromPrivateKeys(
      b_scan: ECPrivateKey.fromHex(given["key_material"]["scan_priv_key"]),
      b_spend: ECPrivateKey.fromHex(given["key_material"]["spend_priv_key"]),
    );

    // Build address list and label map
    final receivingAddressData = _buildAddressesAndLabels(
      silentPaymentOwner,
      given['labels'],
    );
    
    final receivingAddresses = receivingAddressData.addresses;
    final preComputedLabels = receivingAddressData.labelMap;

    // Verify receiving addresses against expected
    for (var address in expected['addresses']) {
      expect(
        receivingAddresses.indexWhere(
          (sp) => sp.toString() == address.toString(),
        ),
        isNot(-1),
        reason: "Address $address not found in receiving addresses",
      );
    }

    // Skip further tests if no input public keys are available
    if (inputPubKeys.isEmpty) {
      continue;
    }

    // Scan outputs to find those belonging to the recipient
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

    // Verify scanned outputs match expected outputs
    final expectedDestinations = expected['outputs'];
    final normalizedOutputs = <String>{};

    // Check each output
    for (int i = 0; i < expectedDestinations.length; i++) {
      final output = addToWallet.entries.elementAt(
        expectedDestinations.length - 1 - i,
      );
      
      final pubkey = output.key;
      final privKeyTweak = output.value.tweak;
      final fullPrivateKey = silentPaymentOwner.b_spend
          .tweak(hexToBytes(privKeyTweak))!
          .xonly;

      // Sign the message with Schnorr
      final signature = signSchnorr(
        Uint8List.fromList(msg),
        fullPrivateKey.data,
        Uint8List.fromList(aux),
      );

      // Build normalized map for comparison
      final outputMap = {
        "pub_key": ECPublicKey.fromHex(pubkey).xhex,
        "priv_key_tweak": privKeyTweak,
        "signature": bytesToHex(signature),
      };

      // Sort keys for consistent string representation
      final sortedMap = Map.fromEntries(
        outputMap.entries.toList()..sort((a, b) => a.key.compareTo(b.key)),
      );

      normalizedOutputs.add(json.encode(sortedMap));
    }

    // Normalize expected outputs for comparison
    final expectedList = List<Map<String, dynamic>>.from(expected["outputs"]);
    final expectedSet = expectedList.map((m) {
      final sorted = Map.fromEntries(
        m.entries.toList()..sort((a, b) => a.key.compareTo(b.key)),
      );
      return json.encode(sorted);
    }).toSet();

    // Verify normalized outputs match expected
    expect(normalizedOutputs, expectedSet, reason: "Output signatures don't match expected");
  }
}

/// Prepare VinInfo objects from the input data in the test vector
List<VinInfo> _prepareVinInfoFromInputs(List<dynamic> inputs) {
  final vins = <VinInfo>[];

  for (final input in inputs) {
    vins.add(
      VinInfo(
        outpoint: OutPoint.fromHex(input['txid'], input['vout']),
        scriptSig: hexToBytes(input['scriptSig']),
        txinwitness: WitnessInput(
          prevOut: OutPoint.fromHex(input['txid'], input['vout']),
          witness: deserStringVector(
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
        privkey: input.containsKey('private_key') 
            ? ECPrivateKey.fromHex(input['private_key']) 
            : null,
      ),
    );
  }

  return vins;
}

/// Extract public and private keys from VinInfo objects
({List<(ECPrivateKey?, bool)> privKeys, List<ECPublicKey> pubKeys}) _extractInputKeysFromVins(
    List<VinInfo> vins) {
  final inputPrivKeys = <(ECPrivateKey?, bool)>[];
  final inputPubKeys = <ECPublicKey>[];

  for (final vin in vins) {
    final pubkey = getPubKeyFromInput(vin);
    if (pubkey == null) continue;

    inputPrivKeys.add((vin.privkey, isP2TR(vin.prevOutScript.compiled)));
    inputPubKeys.add(pubkey);
  }

  return (privKeys: inputPrivKeys, pubKeys: inputPubKeys);
}

/// Build Silent Payment addresses and label map from owner and labels
({List<SilentPaymentAddress> addresses, Map<String, String>? labelMap}) _buildAddressesAndLabels(
    SilentPaymentOwner silentPaymentOwner, List<dynamic> labels) {
  final addresses = <SilentPaymentAddress>[];
  Map<String, String>? preComputedLabels;

  // Add the base address
  addresses.add(silentPaymentOwner.address);

  // G is needed for generating the labels "database"
  final G = ECPublicKey(ECCurve_secp256k1().G.getEncoded());

  // Process each label
  for (var label in labels) {
    addresses.add(silentPaymentOwner.toLabeledAddress(label));
    final generatedLabel = silentPaymentOwner.generateLabel(label);

    preComputedLabels ??= {};
    preComputedLabels[bytesToHex(
      tweakMulPublic(G, generatedLabel),
    )] = bytesToHex(generatedLabel);
  }

  return (addresses: addresses, labelMap: preComputedLabels);
}
