
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:encrypt/encrypt.dart' as encrypt;
import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';
import 'package:pointycastle/src/platform_check/platform_check.dart';


void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Secure Key Generator',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: const KeyGeneratorPage(),
    );
  }
}

pc.AsymmetricKeyPair<pc.RSAPublicKey, pc.RSAPrivateKey> generateRSAkeyPair(
    pc.SecureRandom secureRandom,
    {int bitLength = 2048}) {
  // Create an RSA key generator and initialize it

  // final keyGen = KeyGenerator('RSA'); // Get using registry
  final keyGen = pc.RSAKeyGenerator();

  keyGen.init(pc.ParametersWithRandom(
      pc.RSAKeyGeneratorParameters(BigInt.parse('65537'), bitLength, 64),
      secureRandom));

  // Use the generator

  final pair = keyGen.generateKeyPair();

  // Cast the generated key pair into the RSA key types

  final myPublic = pair.publicKey as pc.RSAPublicKey;
  final myPrivate = pair.privateKey as pc.RSAPrivateKey;

  return pc.AsymmetricKeyPair<pc.RSAPublicKey, pc.RSAPrivateKey>(myPublic, myPrivate);
}

pc.SecureRandom exampleSecureRandom() {

  final secureRandom = pc.SecureRandom('Fortuna')
    ..seed(pc.KeyParameter(
        Platform.instance.platformEntropySource().getBytes(32)));
  return secureRandom;
}

class KeyGeneratorPage extends StatefulWidget {
  const KeyGeneratorPage({super.key});

  @override
  State<KeyGeneratorPage> createState() => _KeyGeneratorPageState();
}

class _KeyGeneratorPageState extends State<KeyGeneratorPage> {
  final _storage = const FlutterSecureStorage();

  Future<void> _generateAndSaveKey() async {
    String? password = await _askPassword(context);
    if (password == null || password.isEmpty) return;
    final passwordHash = sha256Digest(utf8.encode(password));
    await _storage.write(key: 'password', value: base64Encode(passwordHash));
    final pair = generateRSAkeyPair(exampleSecureRandom());
    final public_key_obj = pair.publicKey;
    final private_key_obj = pair.privateKey;
    final private_key = """
-----BEGIN RSA PRIVATE KEY-----
${base64.encode(private_key_obj.toString().codeUnits)}
-----END RSA PRIVATE KEY-----
""";
    final public_key = """
-----BEGIN RSA PUBLIC KEY-----
${base64.encode(public_key_obj.toString().codeUnits)}
-----END RSA PUBLIC KEY-----
""";
    print("XXXX ${private_key}");
    print("XXXX ${public_key}");
    showKeys(private_key, public_key.toString());
    await _storage.write(key: 'private_key', value: private_key);
    await _storage.write(key: 'public_key', value: public_key);
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Private key saved securely!')),
    );
  }

  Future<void> _retrieveAndShowKey() async {
    String? password = await _askPassword(context);
    if (password == null || password.isEmpty) return;
    final hash = sha256Digest(utf8.encode(password));
    final passwordHash = await _storage.read(key: 'password');
    if (base64Encode(hash) == passwordHash) {
      print("XXXXXX PASSWORD OK");
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('PASSWORD OK!')),
      );
    }
     else {      
      print("XXXXXX PASSWORD FAIL");
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('WRONG PASSWORD!')),
      );
      return;
     }

    final private_key = await _storage.read(key: 'private_key');
    final public_key = await _storage.read(key: 'public_key');


    if (private_key == null || public_key == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No key found.')),
      );
      return;
    }
      showKeys(private_key, public_key);
  }

  void showKeys(String private_key, String public_key) {
    showDialog(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Private Key / Public Key'),
          content: SingleChildScrollView(child: Text("$private_key \n $public_key")),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Close'),
            ),
          ],
        ),
      );
  }
  Future<String?> _askPassword(BuildContext context) async {
    String? password;
    await showDialog(
      context: context,
      builder: (context) {
        TextEditingController controller = TextEditingController();
        return AlertDialog(
          title: const Text('Enter Password'),
          content: TextField(
            controller: controller,
            obscureText: true,
            decoration: const InputDecoration(hintText: 'Password'),
          ),
          actions: [
            TextButton(
              onPressed: () {
                password = controller.text;
                Navigator.of(context).pop();
              },
              child: const Text('OK'),
            ),
          ],
        );
      },
    );
    return password;
  }

  Uint8List sha256Digest(Uint8List dataToDigest) {
    final d = pc.SHA256Digest();
    return d.process(dataToDigest);
  }

  encrypt.Key _deriveKey(String password, Uint8List salt) {
    final pbkdf2 = pc.PBKDF2KeyDerivator(pc.HMac(pc.SHA256Digest(), 64))
      ..init(pc.Pbkdf2Parameters(salt, 10000, 32));
    final keyBytes = pbkdf2.process(Uint8List.fromList(utf8.encode(password)));
    return encrypt.Key(keyBytes);
  }

  Uint8List _randomBytes(int length) {
    final rand = Random.secure();
    return Uint8List.fromList(List.generate(length, (_) => rand.nextInt(256)));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Flutter Private Key'),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            ElevatedButton(
              onPressed: _generateAndSaveKey,
              child: const Text('Generate and Save Private Key'),
            ),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: _retrieveAndShowKey,
              child: const Text('Retrieve Private Key'),
            ),
          ],
        ),
      ),
    );
  }
}
