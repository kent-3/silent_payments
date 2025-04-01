// Custom minimal bech32m implementation specifically for Silent Payments
// Based on BIP-350 (https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)

// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';

class Bech32mCodec {
  // Bech32 character set for encoding
  static const String _charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

  // Bech32m constant (different from Bech32)
  static const int _bech32mConstant = 0x2bc830a3;

  /// Encode a Silent Payment address using bech32m
  static String encodeSilentPayment({
    required String hrp,
    required int version,
    required Uint8List B_scan,
    required Uint8List B_spend,
  }) {
    if (version != 0) {
      throw ArgumentError('Only version 0 is currently supported');
    }

    final data = [
      version,
      ..._convertBits([...B_scan, ...B_spend], 8, 5, true),
    ];

    return _encode(hrp, data);
  }

  /// Decode a Silent Payment address
  static Map<String, dynamic> decodeSilentPayment(String address) {
    final decoded = _decode(address);
    if (decoded == null) {
      throw FormatException('Invalid bech32m address');
    }

    final hrp = decoded['hrp'] as String;
    final data = decoded['data'] as List<int>;

    // Validate prefix
    if (hrp != 'sp' && hrp != 'tsp' && hrp != 'sprt') {
      throw FormatException('Invalid prefix: $hrp');
    }

    // Get version
    final version = data[0];
    if (version != 0) {
      throw FormatException('Unsupported version: $version');
    }

    // Convert 5-bit values back to 8-bit bytes
    final keyBytes = _convertBits(data.sublist(1), 5, 8, false);
    if (keyBytes.length != 66) {
      // 33 bytes for scan key + 33 bytes for spend key
      throw FormatException('Invalid key data length');
    }

    return {
      'prefix': hrp,
      'version': version,
      'B_scan': Uint8List.fromList(keyBytes.sublist(0, 33)),
      'B_spend': Uint8List.fromList(keyBytes.sublist(33)),
    };
  }

  /// Encode data with bech32m
  static String _encode(String hrp, List<int> data) {
    // Calculate and append checksum
    final checksum = _createChecksum(hrp, data);
    final values = data + checksum;

    // Build the bech32m string: hrp + '1' + encoded data
    return '${hrp}1${values.map((v) => _charset[v]).join('')}';
  }

  /// Decode a bech32m string
  static Map<String, dynamic>? _decode(String bech) {
    // Validate input
    if (bech.length < 8 || bech.length > 120) {
      return null; // Too short or too long
    }

    // Ensure consistent case (lowercase)
    if (bech.toLowerCase() != bech && bech.toUpperCase() != bech) {
      return null; // Mixed case
    }

    bech = bech.toLowerCase();

    // Find separator
    final separatorPos = bech.lastIndexOf('1');
    if (separatorPos < 1 || separatorPos + 7 > bech.length) {
      return null; // Invalid separator position
    }

    // Extract parts
    final hrp = bech.substring(0, separatorPos);
    final encodedData = bech.substring(separatorPos + 1);

    // Decode data
    final data = <int>[];
    for (int i = 0; i < encodedData.length; i++) {
      final c = encodedData[i];
      final charIdx = _charset.indexOf(c);
      if (charIdx == -1) {
        return null; // Invalid character
      }
      data.add(charIdx);
    }

    // Verify checksum
    if (!_verifyChecksum(hrp, data)) {
      return null; // Invalid checksum
    }

    // Return result without checksum
    return {
      'hrp': hrp,
      'data': data.sublist(0, data.length - 6), // Remove checksum
    };
  }

  /// Create the bech32m checksum
  static List<int> _createChecksum(String hrp, List<int> data) {
    final values = _expandHrp(hrp) + data;
    final polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ _bech32mConstant;

    final checksum = <int>[];
    for (int i = 0; i < 6; i++) {
      checksum.add((polymod >> (5 * (5 - i))) & 31);
    }

    return checksum;
  }

  /// Verify the bech32m checksum
  static bool _verifyChecksum(String hrp, List<int> data) {
    return _polymod(_expandHrp(hrp) + data) == _bech32mConstant;
  }

  /// Expand the human-readable part for checksum calculation
  static List<int> _expandHrp(String hrp) {
    final result = <int>[];

    for (int i = 0; i < hrp.length; i++) {
      result.add(hrp.codeUnitAt(i) >> 5);
    }

    result.add(0);

    for (int i = 0; i < hrp.length; i++) {
      result.add(hrp.codeUnitAt(i) & 31);
    }

    return result;
  }

  /// Perform the polymod calculation for bech32m checksum
  static int _polymod(List<int> values) {
    final generator = [
      0x3b6a57b2,
      0x26508e6d,
      0x1ea119fa,
      0x3d4233dd,
      0x2a1462b3,
    ];
    int chk = 1;

    for (final v in values) {
      final b = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;

      for (int i = 0; i < 5; i++) {
        if ((b >> i) & 1 != 0) {
          chk ^= generator[i];
        }
      }
    }

    return chk;
  }

  /// Convert bits from one base to another
  static List<int> _convertBits(
    List<int> data,
    int fromBits,
    int toBits,
    bool pad,
  ) {
    var acc = 0;
    var bits = 0;
    final maxv = (1 << toBits) - 1;
    final result = <int>[];

    for (final value in data) {
      if (value < 0 || value >> fromBits != 0) {
        throw FormatException('Invalid value: $value');
      }

      acc = (acc << fromBits) | value;
      bits += fromBits;

      while (bits >= toBits) {
        bits -= toBits;
        result.add((acc >> bits) & maxv);
      }
    }

    if (pad) {
      if (bits > 0) {
        result.add((acc << (toBits - bits)) & maxv);
      }
    } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0) {
      throw FormatException('Invalid padding');
    }

    return result;
  }
}
