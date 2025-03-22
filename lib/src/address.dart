// ignore_for_file: constant_identifier_names
// ignore_for_file: non_constant_identifier_names

// TODO: use the ECPrivateKey and ECPublicKey types from coinlib instead?
// import 'package:coinlib/coinlib.dart';

import 'package:blockchain_utils/blockchain_utils.dart';
import 'package:silent_payments/src/utils.dart';

// TODO: allow for multiple accounts
const String SILENT_PAYMENTS_SCAN = "m/352'/0'/0'/1'/0";
const String SILENT_PAYMENTS_SPEND = "m/352'/0'/0'/0'/0";

class SilentPaymentOwner extends SilentPaymentAddress {
  final Secp256k1PrivateKeyEcdsa b_scan;
  final Secp256k1PrivateKeyEcdsa b_spend;

  SilentPaymentOwner({
    required super.version,
    required super.B_scan,
    required super.B_spend,
    required this.b_scan,
    required this.b_spend,
  }) : super();

  factory SilentPaymentOwner.fromPrivateKeys({
    required Secp256k1PrivateKeyEcdsa b_scan,
    required Secp256k1PrivateKeyEcdsa b_spend,
    int? version,
  }) {
    return SilentPaymentOwner(
      b_scan: b_scan,
      b_spend: b_spend,
      B_scan: Secp256k1PublicKeyEcdsa.fromBytes(b_scan.publicKey.compressed),
      B_spend: Secp256k1PublicKeyEcdsa.fromBytes(b_spend.publicKey.compressed),
      version: version ?? 0,
    );
  }

  factory SilentPaymentOwner.fromBip32(
    Bip32Slip10Secp256k1 bip32, {
    int? version,
  }) {
    final scanDerivation = bip32.derivePath(SILENT_PAYMENTS_SCAN);
    final spendDerivation = bip32.derivePath(SILENT_PAYMENTS_SPEND);

    return SilentPaymentOwner(
      b_scan: Secp256k1PrivateKeyEcdsa.fromBytes(scanDerivation.privateKey.raw),
      b_spend: Secp256k1PrivateKeyEcdsa.fromBytes(
        spendDerivation.privateKey.raw,
      ),
      B_scan: Secp256k1PublicKeyEcdsa.fromBytes(
        scanDerivation.publicKey.compressed,
      ),
      B_spend: Secp256k1PublicKeyEcdsa.fromBytes(
        spendDerivation.publicKey.compressed,
      ),
      version: version ?? 0,
    );
  }

  factory SilentPaymentOwner.fromMnemonic(
    String mnemonic, {
    String? network,
    int? version,
  }) {
    return SilentPaymentOwner.fromBip32(
      Bip32Slip10Secp256k1.fromSeed(
        Bip39MnemonicDecoder().decode(mnemonic),
        network ==
                'BitcoinNetwork.testnet' // TODO: use enum
            ? Bip32Const.testNetKeyNetVersions
            : Bip32Const.mainNetKeyNetVersions,
      ),
      version: version,
    );
  }

  List<int> generateLabel(int m) {
    return taggedHash(concatBytes([b_scan.raw, serUint32(m)]), "BIP0352/Label");
  }

  SilentPaymentOwner toLabeledSilentPaymentAddress(int m) {
    final tweak = BigintUtils.fromBytes(generateLabel(m));
    final tweakedKey = B_spend.point + (Curves.generatorSecp256k1 * tweak);
    final B_m = Secp256k1PublicKeyEcdsa.fromBytes(tweakedKey.toBytes());

    return SilentPaymentOwner(
      b_scan: b_scan,
      b_spend: b_spend,
      B_scan: B_scan,
      B_spend: B_m,
      version: version,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'version': version,
      'B_scan': B_scan.toHex(),
      'B_spend': B_spend.toHex(),
      'b_scan': b_scan.toHex(),
      'b_spend': b_spend.toHex(),
    };
  }

  static SilentPaymentOwner fromJson(Map<String, dynamic> json) {
    return SilentPaymentOwner(
      version: json['version'] as int,
      B_scan: Secp256k1PublicKeyEcdsa.fromBytes(
        hex.decode(json['B_scan'] as String),
      ),
      B_spend: Secp256k1PublicKeyEcdsa.fromBytes(
        hex.decode(json['B_spend'] as String),
      ),
      b_scan: Secp256k1PrivateKeyEcdsa.fromBytes(
        hex.decode(json['b_scan'] as String),
      ),
      b_spend: Secp256k1PrivateKeyEcdsa.fromBytes(
        hex.decode(json['b_spend'] as String),
      ),
    );
  }
}

class SilentPaymentDestination extends SilentPaymentAddress {
  SilentPaymentDestination({
    required super.version,
    required Secp256k1PublicKeyEcdsa scanPubkey,
    required Secp256k1PublicKeyEcdsa spendPubkey,
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

  final Secp256k1PublicKeyEcdsa B_scan;
  final Secp256k1PublicKeyEcdsa B_spend;
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
      B_scan: Secp256k1PublicKeyEcdsa.fromBytes(key.sublist(0, 33)),
      B_spend: Secp256k1PublicKeyEcdsa.fromBytes(key.sublist(33)),
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

    final bytes = [...B_scan.compressed, ...B_spend.compressed];

    return Bech32EncoderBase.encodeBech32(
      prefix,
      [version, ...Bech32BaseUtils.convertToBase32(bytes)],
      SegwitBech32Const.separator,
      (hrp, data) =>
          Bech32Utils.computeChecksum(hrp, data, Bech32Encodings.bech32m),
    );
  }
}
