// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';
import 'dart:convert';
import 'package:coinlib/coinlib.dart';
import 'package:convert/convert.dart';
import 'package:elliptic/elliptic.dart';
import 'package:crypto/crypto.dart';

final NUMS_H = BigInt.parse(
  "0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
);

final Uint8List numsHBytes = Uint8List.fromList(
  hexToBytes(NUMS_H.toRadixString(16).padLeft(64, '0')),
);

int deserCompactSize(ByteData f) {
  final view = f.buffer;
  int nbytes = view.lengthInBytes;
  if (nbytes == 0) {
    return 0; // end of stream
  }

  int nit = f.getUint8(0);
  if (nit == 253) {
    nit = f.getUint16(1, Endian.little);
  } else if (nit == 254) {
    nit = f.getUint32(3, Endian.little);
  } else if (nit == 255) {
    nit = f.getUint64(7, Endian.little);
  }
  return nit;
}

ByteData deserString(ByteData f) {
  final nit = deserCompactSize(f);
  int offset = 1;
  return ByteData.sublistView(
    f.buffer.asUint8List().sublist(offset, nit + offset),
  );
}

List<ByteData> deserStringVector(ByteData f) {
  int offset = 0;

  final nit = deserCompactSize(f);
  offset += 1;

  List<ByteData> result = [];
  for (int i = 0; i < nit; i++) {
    final t = deserString(
      ByteData.sublistView(f.buffer.asUint8List().sublist(offset)),
    );

    result.add(t);
    offset += t.lengthInBytes + 1;
  }
  return result;
}

class VinInfo {
  final OutPoint outpoint;
  final List<int> scriptSig;
  final WitnessInput? txinwitness;
  final Script prevOutScript;
  final ECPrivateKey? privkey;

  VinInfo({
    required this.outpoint,
    required this.scriptSig,
    required this.txinwitness,
    required this.prevOutScript,
    this.privkey,
  });
}

ECPublicKey? getPubKeyFromInput(VinInfo vin) {
  final spk = vin.prevOutScript.compiled; // spk = scriptPubkey

  if (isP2PKH(spk)) {
    final spkHash = spk.sublist(3, 3 + 20); // 20-byte pubkey hash

    // inefficient scan for compressed pubkey at the end of scriptSig
    final sig = vin.scriptSig;
    for (int i = sig.length; i >= 33; i--) {
      final pubkeyBytes = Uint8List.fromList(sig.sublist(i - 33, i));
      final pubkeyHash = hash160(pubkeyBytes);

      if (_listEquals(pubkeyHash, spkHash)) {
        final pubkey = ECPublicKey(pubkeyBytes);
        return pubkey.compressed ? pubkey : null;
      }
    }
  }

  if (isP2SH(spk)) {
    final scriptSig = vin.scriptSig;
    if (scriptSig.isEmpty) return null;

    // TODO: better type conversions?
    final redeemScript = Uint8List.fromList(
      scriptSig.sublist(1),
    ); // skip push opcode
    if (isP2WPKH(redeemScript) && vin.txinwitness != null) {
      final stack = vin.txinwitness!.witness;
      if (stack.isNotEmpty) {
        final pubkeyBytes = stack.last;
        final pubkey = ECPublicKey(pubkeyBytes);
        return pubkey.compressed ? pubkey : null;
      }
    }
  }

  if (isP2WPKH(spk) && vin.txinwitness != null) {
    final stack = vin.txinwitness!.witness;
    if (stack.isNotEmpty) {
      final pubkeyBytes = stack.last;
      final pubkey = ECPublicKey(pubkeyBytes);
      return pubkey.compressed ? pubkey : null;
    }
  }

  if (isP2TR(spk) && vin.txinwitness != null) {
    final stack = List<Uint8List>.from(vin.txinwitness!.witness);
    if (stack.isNotEmpty) {
      // Check for annex (starts with 0x50)
      if (stack.length > 1 && stack.last.isNotEmpty && stack.last[0] == 0x50) {
        stack.removeLast();
      }

      // Script path spend
      if (stack.length > 1) {
        final controlBlock = stack.last;
        if (controlBlock.length >= 33) {
          final internalKey = controlBlock.sublist(1, 33);
          if (_listEquals(internalKey, numsHBytes)) {
            return null;
          }
        }
      }

      // key path spend
      final pubkeyBytes = spk.sublist(2);
      return ECPublicKey.fromXOnly(pubkeyBytes);
    }
  }

  return null;
}

bool _listEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

bool isP2TR(Uint8List spk) {
  // P2TR = OP_1 (0x51) + OP_PUSHBYTES_32 (0x20) + 32 bytes
  return spk.length == 34 && spk[0] == 0x51 && spk[1] == 0x20;
}

bool isP2WPKH(Uint8List spk) {
  // P2WPKH = OP_0 (0x00) + OP_PUSHBYTES_20 (0x14) + 20 bytes
  return spk.length == 22 && spk[0] == 0x00 && spk[1] == 0x14;
}

bool isP2SH(Uint8List spk) {
  // P2SH = OP_HASH160 (0xA9) + OP_PUSHBYTES_20 (0x14) + 20 bytes + OP_EQUAL (0x87)
  return spk.length == 23 &&
      spk[0] == 0xA9 &&
      spk[1] == 0x14 &&
      spk[22] == 0x87;
}

bool isP2PKH(Uint8List spk) {
  // P2PKH = OP_DUP (0x76) + OP_HASH160 (0xA9) + OP_PUSHBYTES_20 (0x14) + 20 bytes + OP_EQUALVERIFY (0x88) + OP_CHECKSIG (0xAC)
  return spk.length == 25 &&
      spk[0] == 0x76 &&
      spk[1] == 0xA9 &&
      spk[2] == 0x14 &&
      spk[23] == 0x88 &&
      spk[24] == 0xAC;
}

// NOTE: Code below is to match the implementation of Schnorr signatures used by the
// [python reference](https://github.com/bitcoin/bips/blob/master/bip-0352/reference.py)

final curve = getSecp256k1();
final n = curve.n;
final G = curve.G;

Uint8List taggedHash(String tag, List<int> msg) {
  final tagHash = sha256.convert(utf8.encode(tag)).bytes;
  final h = sha256.convert([...tagHash, ...tagHash, ...msg]);
  return Uint8List.fromList(h.bytes);
}

/// Produces a Schnorr signature per BIP-340, matching the test Python implementation.
Uint8List signSchnorr(
  Uint8List msg, // 32-byte message
  Uint8List privKeyBytes, // 32-byte scalar
  Uint8List auxRand, // 32-byte aux
) {
  assert(msg.length == 32);
  assert(auxRand.length == 32);
  final privKey = BigInt.parse(hex.encode(privKeyBytes), radix: 16);

  // Step 1: t = privKey XOR TaggedHash("BIP0340/aux", auxRand)
  final auxHash = taggedHash("BIP0340/aux", auxRand);
  final t = privKey ^ BigInt.parse(hex.encode(auxHash), radix: 16);

  // Step 2: nonce = TaggedHash("BIP0340/nonce", t || pubkey || msg)
  final privateKey = PrivateKey(curve, privKey);
  final pubkey = privateKey.publicKey;
  final pubkeyBytes = pubkey.X.toRadixString(16).padLeft(64, '0');

  Uint8List bigIntTo32Bytes(BigInt value) {
    final bytes = value.toUnsigned(256).toRadixString(16).padLeft(64, '0');
    return Uint8List.fromList(hex.decode(bytes));
  }

  final nonceInput = <int>[
    ...bigIntTo32Bytes(t),
    ...hex.decode(pubkeyBytes),
    ...msg,
  ];
  final nonceBytes = taggedHash("BIP0340/nonce", nonceInput);
  BigInt k = BigInt.parse(hex.encode(nonceBytes), radix: 16) % n;
  if (k == BigInt.zero) {
    throw Exception("Nonce k == 0");
  }

  // Step 3: Compute R = k*G and ensure Y is even
  var kKey = PrivateKey(curve, k);
  var R = kKey.publicKey;

  if (!R.Y.isEven) {
    k = n - k;
    kKey = PrivateKey(curve, k);
    R = kKey.publicKey;
  }

  final rBytes = R.X.toRadixString(16).padLeft(64, '0');
  final rBytesList = hex.decode(rBytes);

  // Step 4: Compute e = TaggedHash("BIP0340/challenge", r || pubkey || msg)
  final eBytes = taggedHash("BIP0340/challenge", [
    ...rBytesList,
    ...hex.decode(pubkeyBytes),
    ...msg,
  ]);
  final e = BigInt.parse(hex.encode(eBytes), radix: 16) % n;

  // Step 5: s = (k + e * privKey) % n
  final s = (k + e * privKey) % n;
  final sBytes = s.toRadixString(16).padLeft(64, '0');
  final sBytesList = hex.decode(sBytes);

  // Final signature = r || s
  return Uint8List.fromList([...rBytesList, ...sBytesList]);
}
