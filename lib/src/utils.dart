import 'package:blockchain_utils/utils/numbers/utils/bigint_utils.dart';
import 'package:blockchain_utils/crypto/quick_crypto.dart';

List<int> serUint32(int n) {
  return BigintUtils.toBytes(BigInt.from(n), length: 4);
}

List<int> concatBytes(List<List<int>> lists) {
  var totalLength = lists.fold<int>(0, (sum, list) => sum + list.length);
  var result = List<int>.filled(totalLength, 0);
  var offset = 0;

  for (var list in lists) {
    result.setRange(offset, offset + list.length, list);
    offset += list.length;
  }

  return result;
}

/// Function: taggedHash
/// Description: Computes a tagged hash of the input data with a provided tag.
/// Input:
///   - `List<int>` data - The data to be hashed.
///   - String tag - A unique tag to differentiate the hash.
/// Output: `List<int>` - The resulting tagged hash.
/// Note: This function combines the provided tag with the input data to create a unique
/// hash by applying a double SHA-256 hash.
List<int> taggedHash(List<int> data, String tag) {
  /// Calculate the hash of the tag as List<int>.
  final tagDigest = QuickCrypto.sha256Hash(List<int>.from(tag.codeUnits));

  /// Concatenate the tag hash with itself and the input data.
  final concat = List<int>.from([...tagDigest, ...tagDigest, ...data]);

  /// Compute a double SHA-256 hash of the concatenated data.
  return QuickCrypto.sha256Hash(concat);
}
