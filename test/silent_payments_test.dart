import 'dart:typed_data';
import 'package:coinlib/coinlib.dart';
import 'package:test/test.dart';
import 'package:silent_payments/silent_payments.dart';

void main() async {
  await loadCoinlib();
  group('SilentPaymentAddress', () {
    test('can parse a valid silent payment address', () {
      const address =
          'sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv';
      final spa = SilentPaymentAddress.fromAddress(address);

      expect(spa.version, 0);
      expect(spa.B_scan.data.length, 33);
      expect(spa.B_spend.data.length, 33);
    });

    test('toString returns same address', () {
      const address =
          'tsp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc3wk4yh';
      final spa = SilentPaymentAddress.fromAddress(address);

      expect(spa.toString(network: 'BitcoinNetwork.testnet'), address);
    });

    test('throws on invalid prefix', () {
      expect(
        () => SilentPaymentAddress.fromAddress('abc1qqq...'),
        throwsA(isA<Exception>()),
      );
    });

    test('throws on non-zero version', () {
      expect(
        () => SilentPaymentAddress(
          B_scan: ECPublicKey(Uint8List(33)),
          B_spend: ECPublicKey(Uint8List(33)),
          version: 1,
        ),
        throwsA(isA<Exception>()),
      );
    });
  });
}
