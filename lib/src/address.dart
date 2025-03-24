// ignore_for_file: constant_identifier_names
// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';
import 'package:coinlib/coinlib.dart';
import 'package:blockchain_utils/bech32/bech32.dart';
import 'package:silent_payments/src/utils.dart';

// TODO: allow for multiple accounts
const String SILENT_PAYMENTS_SCAN = "m/352'/0'/0'/1'/0";
const String SILENT_PAYMENTS_SPEND = "m/352'/0'/0'/0'/0";

class SilentPaymentOwner extends SilentPaymentAddress {
  final ECPrivateKey b_scan;
  final ECPrivateKey b_spend;

  SilentPaymentOwner({
    required super.version,
    required super.B_scan,
    required super.B_spend,
    required this.b_scan,
    required this.b_spend,
  }) : super();

  factory SilentPaymentOwner.fromPrivateKeys({
    required ECPrivateKey b_scan,
    required ECPrivateKey b_spend,
    int? version,
  }) {
    return SilentPaymentOwner(
      b_scan: b_scan,
      b_spend: b_spend,
      B_scan: b_scan.pubkey,
      B_spend: b_spend.pubkey,
      version: version ?? 0,
    );
  }

  factory SilentPaymentOwner.fromBip32(HDPrivateKey bip32, {int? version}) {
    final scanDerivation = bip32.derivePath(SILENT_PAYMENTS_SCAN);
    final spendDerivation = bip32.derivePath(SILENT_PAYMENTS_SPEND);

    return SilentPaymentOwner(
      b_scan: scanDerivation.privateKey,
      b_spend: spendDerivation.privateKey,
      B_scan: scanDerivation.publicKey,
      B_spend: spendDerivation.publicKey,
      version: version ?? 0,
    );
  }

  factory SilentPaymentOwner.fromSeed(
    Uint8List seed, {
    String? network,
    int? version,
  }) {
    return SilentPaymentOwner.fromBip32(
      HDPrivateKey.fromSeed(seed), // TODO: support specifying testnet here
      version: version,
    );
  }

  Uint8List generateLabel(int m) {
    return taggedHash([...b_scan.data, ...serUint32(m)], "BIP0352/Label");
  }

  SilentPaymentOwner toLabeledSilentPaymentAddress(int m) {
    final B_m = B_spend.tweak(generateLabel(m));
    return SilentPaymentOwner(
      b_scan: b_scan,
      b_spend: b_spend,
      B_scan: B_scan,
      B_spend: B_m!,
      version: version,
    );
  }

  // TODO: decide if keys should be stored as hex String or Uint8List, or not at all
  Map<String, dynamic> toJson() {
    return {
      'version': version,
      'B_scan': B_scan.hex,
      'B_spend': B_spend.hex,
      'b_scan': b_scan.data,
      'b_spend': b_spend.data,
    };
  }

  static SilentPaymentOwner fromJson(Map<String, dynamic> json) {
    return SilentPaymentOwner(
      version: json['version'] as int,
      B_scan: ECPublicKey.fromHex(json['B_scan'] as String),
      B_spend: ECPublicKey.fromHex(json['B_spend'] as String),
      b_scan: ECPrivateKey(json['b_scan'] as Uint8List),
      b_spend: ECPrivateKey(json['b_spend'] as Uint8List),
    );
  }
}

class SilentPaymentDestination extends SilentPaymentAddress {
  SilentPaymentDestination({
    required super.version,
    required ECPublicKey scanPubkey,
    required ECPublicKey spendPubkey,
    required this.amount,
  }) : super(B_scan: scanPubkey, B_spend: spendPubkey);

  int amount;

  factory SilentPaymentDestination.fromAddress(String address, int amount) {
    final receiver = SilentPaymentAddress.fromAddress(address);

    return SilentPaymentDestination(
      scanPubkey: receiver.B_scan,
      spendPubkey: receiver.B_spend,
      version: receiver.version,
      amount: amount,
    );
  }
}

class SilentPaymentAddress {
  static RegExp get regex => RegExp(r'(tsp|sp|sprt)1[0-9a-zA-Z]{113}');

  final ECPublicKey B_scan;
  final ECPublicKey B_spend;
  final int version;

  SilentPaymentAddress({
    required this.B_scan,
    required this.B_spend,
    this.version = 0,
  }) {
    if (version != 0) {
      throw Exception("Can't have other version than 0 for now");
    }
  }

  factory SilentPaymentAddress.fromAddress(String address) {
    final decoded = Bech32DecoderBase.decodeBech32(
      address,
      SegwitBech32Const.separator,
      SegwitBech32Const.checksumStrLen,
      (hrp, data) =>
          Bech32Utils.verifyChecksum(hrp, data, Bech32Encodings.bech32m),
    );
    final prefix = decoded.item1;
    final words = decoded.item2;

    if (prefix != 'sp' && prefix != 'sprt' && prefix != 'tsp') {
      throw Exception('Invalid prefix: $prefix');
    }

    final version = words[0];
    if (version != 0) throw ArgumentError('Invalid version');

    final key = Bech32BaseUtils.convertFromBase32(words.sublist(1));

    return SilentPaymentAddress(
      B_scan: ECPublicKey(Uint8List.fromList(key.sublist(0, 33))),
      B_spend: ECPublicKey(Uint8List.fromList(key.sublist(33))),
      version: version,
    );
  }

  @override
  String toString({String? network}) {
    final prefix = switch (network) {
      'BitcoinNetwork.testnet' => 'tsp',
      'BitcoinNetwork.regtest' => 'sprt',
      _ => 'sp',
    };

    final bytes = [...B_scan.data, ...B_spend.data];

    return Bech32EncoderBase.encodeBech32(
      prefix,
      [version, ...Bech32BaseUtils.convertToBase32(bytes)],
      SegwitBech32Const.separator,
      (hrp, data) =>
          Bech32Utils.computeChecksum(hrp, data, Bech32Encodings.bech32m),
    );
  }
}
