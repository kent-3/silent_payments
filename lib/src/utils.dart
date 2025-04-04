// ignore_for_file: non_constant_identifier_names

import 'dart:convert';
import 'dart:typed_data';
import 'package:coinlib/coinlib.dart';
import 'package:pointycastle/ecc/api.dart' show ECPoint;
import 'package:pointycastle/ecc/ecc_fp.dart' show ECCurve;
import 'package:pointycastle/ecc/curves/secp256k1.dart' show ECCurve_secp256k1;

// =====================================================================
// Utility Extensions and Functions
// =====================================================================

/// Extension methods for ECPublicKey
extension ECPublicKeyExtensions on ECPublicKey {
  /// Create a negated version of this public key (same x, negated y)
  ECPublicKey negate() {
    final curve = ECCurve_secp256k1().curve as ECCurve;
    final point = curve.decodePoint(data)!;

    final x = point.x!.toBigInteger()!;
    final y = point.y!.toBigInteger()!;
    final q = curve.q!;

    final negatedY = (q - y) % q;
    final negatedPoint = curve.createPoint(x, negatedY);

    return ECPublicKey(negatedPoint.getEncoded(true));
  }

  /// Add this public key to another
  ECPublicKey add(ECPublicKey other) {
    final p1 = decodePoint(this);
    final p2 = decodePoint(other);
    final sum = (p1 + p2)!;

    if (sum.isInfinity) {
      throw Exception("addPubkeys: result is point at infinity");
    }

    return ECPublicKey(sum.getEncoded(true));
  }
}

/// Extension methods for ECPrivateKey
extension ECPrivateKeyExtensions on ECPrivateKey {
  /// Create a negated version of this private key
  ECPrivateKey negate() {
    final n = ECCurve_secp256k1().n;
    final k = bigIntFromBytes(data);
    final negated = (n - k) % n;
    return ECPrivateKey(bigIntToBytes(negated, length: 32));
  }
}

/// Simple serialization of a 32-bit integer
List<int> serUint32(int n) {
  final byteData = ByteData(4);
  byteData.setUint32(0, n, Endian.big);
  return byteData.buffer.asUint8List();
}

/// Create a tagged hash from data and tag
Uint8List taggedHash(List<int> data, String tag) {
  final tagDigest = sha256Hash(utf8.encode(tag));
  final concat = Uint8List.fromList([...tagDigest, ...tagDigest, ...data]);
  return sha256Hash(concat);
}

/// Multiply a private key by a tweak
Uint8List tweakMulPrivate(Uint8List keyBytes, Uint8List tweakBytes) {
  final n = ECCurve_secp256k1().n;

  final keyInt = bigIntFromBytes(keyBytes);
  final tweakInt = bigIntFromBytes(tweakBytes);

  final result = (keyInt * tweakInt) % n;
  return bigIntToBytes(result, length: 32);
}

/// Multiply a public key by a tweak
Uint8List tweakMulPublic(ECPublicKey key, Uint8List tweakBytes) {
  final point = decodePoint(key);
  final tweakInt = bigIntFromBytes(tweakBytes);

  final result = (point * tweakInt)!;
  return result.getEncoded(true); // compressed
}

/// Convert a byte array to a BigInt
BigInt bigIntFromBytes(Uint8List bytes, {Endian endian = Endian.big}) {
  if (endian == Endian.little) {
    bytes = Uint8List.fromList(bytes.reversed.toList());
  }

  BigInt result = BigInt.zero;
  for (final byte in bytes) {
    result = (result << 8) | BigInt.from(byte);
  }
  return result;
}

/// Convert a BigInt to a byte array
Uint8List bigIntToBytes(
  BigInt val, {
  required int length,
  Endian order = Endian.big,
}) {
  if (val == BigInt.zero) {
    return Uint8List(length);
  }

  final result = Uint8List(length);
  final bigMask = BigInt.from(0xff);

  for (int i = 0; i < length; i++) {
    result[length - i - 1] = (val & bigMask).toInt();
    val = val >> 8;
  }

  if (order == Endian.little) {
    return Uint8List.fromList(result.reversed.toList());
  }

  return result;
}

/// Decode a public key into an ECPoint
ECPoint decodePoint(ECPublicKey pubkey) {
  final curve = ECCurve_secp256k1().curve;
  return curve.decodePoint(pubkey.data)!;
}
