import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:coinlib/coinlib.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart' show ECCurve_secp256k1;

import 'package:silent_payments/src/utils.dart';

void main() async {
  await loadCoinlib();

  test('negatePubkey correctly negates a point on secp256k1', () {
    final secp256k1 = ECCurve_secp256k1();
    final G = secp256k1.G; // base point

    // Compress the base point
    final compressed = G.getEncoded(true);
    final pubkey = ECPublicKey(Uint8List.fromList(compressed));

    final negated = negatePubkey(pubkey);

    final point = secp256k1.curve.decodePoint(pubkey.data)!;
    final negatedPoint = secp256k1.curve.decodePoint(negated.data)!;

    // Check that P + (-P) = point at infinity (identity)
    final sum = point + negatedPoint;
    expect(sum!.isInfinity, isTrue);

    // Check that X coordinate remains the same
    expect(point.x!.toBigInteger(), equals(negatedPoint.x!.toBigInteger()));

    // Check that Y coordinate is not equal (i.e. flipped)
    expect(
      point.y!.toBigInteger(),
      isNot(equals(negatedPoint.y!.toBigInteger())),
    );
  });
}
