// ignore_for_file: non_constant_identifier_names

import 'dart:convert';
import 'dart:typed_data';
import 'package:coinlib/coinlib.dart';
// import 'package:pointycastle/ecc/api.dart' show ECPoint;
import 'package:pointycastle/ecc/curves/secp256k1.dart' show ECCurve_secp256k1;

List<int> serUint32(int n) {
  final byteData = ByteData(4);
  byteData.setUint32(0, n, Endian.big);
  return byteData.buffer.asUint8List();
}

/// Note: This function combines the provided tag with the input data to create a unique
/// hash by applying a double SHA-256 hash.
Uint8List taggedHash(List<int> data, String tag) {
  final tagDigest = sha256Hash(utf8.encode(tag));
  final concat = Uint8List.fromList([...tagDigest, ...tagDigest, ...data]);
  return sha256Hash(concat);
}

Uint8List tweakMul(Uint8List keyBytes, Uint8List tweakBytes) {
  final n = ECCurve_secp256k1().n;

  final keyInt = bigIntFromBytes(keyBytes);
  final tweakInt = bigIntFromBytes(tweakBytes);

  final result = (keyInt * tweakInt) % n;
  return bigIntToBytes(result, length: 32);
}

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

// TODO: do we actually need any of this?

// final NUMS_H = BigInt.parse(
//   "0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
// );

// int deserCompactSize(ByteData f) {
//   final view = f.buffer;
//   int nbytes = view.lengthInBytes;
//   if (nbytes == 0) {
//     return 0; // end of stream
//   }
//
//   int nit = f.getUint8(0);
//   if (nit == 253) {
//     nit = f.getUint16(1, Endian.little);
//   } else if (nit == 254) {
//     nit = f.getUint32(3, Endian.little);
//   } else if (nit == 255) {
//     nit = f.getUint64(7, Endian.little);
//   }
//   return nit;
// }

// ByteData deserString(ByteData f) {
//   final nit = deserCompactSize(f);
//   int offset = 1;
//   return ByteData.sublistView(
//     f.buffer.asUint8List().sublist(offset, nit + offset),
//   );
// }

// List<ByteData> deserStringVector(ByteData f) {
//   int offset = 0;
//
//   final nit = deserCompactSize(f);
//   offset += 1;
//
//   List<ByteData> result = [];
//   for (int i = 0; i < nit; i++) {
//     final t = deserString(
//       ByteData.sublistView(f.buffer.asUint8List().sublist(offset)),
//     );
//
//     result.add(t);
//     offset += t.lengthInBytes + 1;
//   }
//   return result;
// }

// class VinInfo {
//   final OutPoint outpoint;
//   final List<int> scriptSig;
//   final WitnessInput txinwitness;
//   final Script prevOutScript;
//   final ECPrivateKey? privkey;
//
//   VinInfo({
//     required this.outpoint,
//     required this.scriptSig,
//     required this.txinwitness,
//     required this.prevOutScript,
//     this.privkey,
//   });
// }

// ECPublicKey? getPubkeyFromInput(VinInfo vin) {
//   switch (vin.prevOutScript.getAddressType()) {
//         case BitcoinAddressType.p2pkh:
//       for (var i = vin.scriptSig.length; i >= 33; i--) {
//         final pubkeyBytes = vin.scriptSig.sublist(i - 33, i);
//         final pubkeyHash = hash160(pubkeyBytes);
//         final expectedHash = vin.prevOutScript.addressProgram;
//         if (bytesEqual(pubkeyHash, expectedHash)) {
//           return ECPublicKey(Uint8List.fromList(pubkeyBytes));
//         }
//       }
//       break;
//     case P2shAddressType.p2pkhInP2sh:
//       final redeemScript = vin.scriptSig.sublist(1);
//       if (Script.fromRaw(bytes: redeemScript).getAddressType() ==
//           SegwitAddressType.p2wpkh) {
//         return ECPublic.fromBytes(
//           vin.txinwitness.scriptWitness.stack.last.buffer.asUint8List(),
//         );
//       }
//       break;
//     case SegwitAddressType.p2wpkh:
//       return ECPublic.fromBytes(
//         vin.txinwitness.scriptWitness.stack.last.buffer.asUint8List(),
//       );
//     case SegwitAddressType.p2tr:
//       final witnessStack = vin.txinwitness.scriptWitness.stack;
//       if (witnessStack.isNotEmpty) {
//         if (witnessStack.length > 1 &&
//             witnessStack.last.buffer.asUint8List()[0] == 0x50) {
//           witnessStack.removeLast();
//         }
//
//         if (witnessStack.length > 1) {
//           final controlBlock = witnessStack.last.buffer.asUint8List();
//           final internalKey = controlBlock.sublist(1, 33);
//           if (BytesUtils.compareBytes(
//                 internalKey,
//                 BigintUtils.toBytes(NUMS_H, length: 32, order: Endian.big),
//               ) ==
//               0) {
//             return null;
//           }
//         }
//         return ECPublic.fromBytes(vin.prevOutScript.toBytes().sublist(2));
//       }
//       break;
//     default:
//       return null;
//   }
//
//   return null;
// }

// enum BitcoinAddressType { p2pkh, p2sh, p2wpkh, p2wsh, p2tr, p2pk, unknown }
//
// bool matchesOps(List<ScriptOp> ops, List<dynamic> pattern) {
//   if (ops.length != pattern.length) return false;
//   for (int i = 0; i < pattern.length; i++) {
//     final expected = pattern[i];
//     final actual = ops[i];
//
//     if (expected is String) {
//       if (!(actual is ScriptOpCode &&
//           actual.code == ScriptOpCode.fromName(expected).code)) {
//         return false;
//       }
//     } else if (expected is int) {
//       if (!(actual is ScriptPushData && actual.data.length == expected)) {
//         return false;
//       }
//     } else {
//       return false;
//     }
//   }
//   return true;
// }
//
// extension ScriptAddressType on Script {
//   BitcoinAddressType getAddressType() {
//     final ops = this.ops;
//
//     if (matchesOps(ops, ["DUP", "HASH160", 20, "EQUALVERIFY", "CHECKSIG"])) {
//       return BitcoinAddressType.p2pkh;
//     }
//
//     if (matchesOps(ops, ["HASH160", 20, "EQUAL"])) {
//       return BitcoinAddressType.p2sh;
//     }
//
//     if (matchesOps(ops, ["0", 20])) {
//       return BitcoinAddressType.p2wpkh;
//     }
//
//     if (matchesOps(ops, ["0", 32])) {
//       return BitcoinAddressType.p2wsh;
//     }
//
//     if (matchesOps(ops, ["1", 32])) {
//       return BitcoinAddressType.p2tr;
//     }
//
//     if (matchesOps(ops, [33, "CHECKSIG"])) {
//       return BitcoinAddressType.p2pk;
//     }
//
//     return BitcoinAddressType.unknown;
//   }
// }
//
