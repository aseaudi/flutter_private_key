import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:googleapis/drive/v3.dart' as ga;
import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';
import 'package:pointycastle/src/platform_check/platform_check.dart';
import 'package:http/io_client.dart';
import 'package:http/http.dart' as http;
import 'package:file_picker/file_picker.dart';
import 'package:path_provider/path_provider.dart';

final GoogleSignIn _googleSignIn = GoogleSignIn(
    // Optional clientId
    // clientId: '258477920845-trq70918u2a5cngo317aro0n6gg9813j.apps.googleusercontent.com',
    // scopes: <String>[PeopleServiceApi.contactsReadonlyScope],
    scopes: <String>[
      // 'https://www.googleapis.com/auth/drive',
      'https://www.googleapis.com/auth/drive.appdata',
      'https://www.googleapis.com/auth/userinfo.email',
    ]);

class GoogleHttpClient extends IOClient {
  Map<String, String> _headers;

  GoogleHttpClient(this._headers) : super();

  @override
  Future<IOStreamedResponse> send(http.BaseRequest request) =>
      super.send(request..headers.addAll(_headers));

  @override
  Future<http.Response> head(Uri url, {Map<String, String>? headers}) =>
      super.head(url, headers: headers!..addAll(_headers));
}

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

  return pc.AsymmetricKeyPair<pc.RSAPublicKey, pc.RSAPrivateKey>(
      myPublic, myPrivate);
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
  GoogleSignInAccount? _currentUser;
  final storage = FlutterSecureStorage();
  late ga.FileList list;

  @override
  void initState() {
    super.initState();
    _googleSignIn.onCurrentUserChanged.listen((GoogleSignInAccount? account) {
      setState(() {
        _currentUser = account;
      });
      if (_currentUser != null) {
        // _handleGetContact();
      }
    });
    _googleSignIn.signInSilently();
  }

  Future<void> _handleSignIn() async {
    print("XXXXXX handlesignin");
    try {
      await _googleSignIn.signIn();
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('SIGN IN OK!')),
      );
      print("XXXXXX Success in handlesignin");
    } catch (error) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('SIGN IN FAILED!')),
      );
      print("XXXXXX Error in handlesignin");
      print(error); // ignore: avoid_print
    }
  }

  Future<void> _handleSignOut() async {
    _googleSignIn.disconnect();
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('SIGN OUT OK!')),
    );
  }

  _uploadFileToGoogleDrive() async {
    if (!_isSignedIn()) return;
    var client = GoogleHttpClient(await _currentUser!.authHeaders);
    var drive = ga.DriveApi(client);
    ga.File fileToUpload = ga.File();
    final private_key = await _storage.read(key: 'private_key');
    if (private_key == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No key found.')),
      );
      return;
    }
    final dir = await getApplicationDocumentsDirectory();
    final file = File('${dir.path}/private_key');
    await file.writeAsString(private_key!);
    // var file = await FilePicker.getFile();
    fileToUpload.parents = ["appDataFolder"];
    fileToUpload.name = "private_key";
    var response = await drive.files.create(
      fileToUpload,
      uploadMedia: ga.Media(file.openRead(), file.lengthSync()),
    );
    print("XXXXXX upload file to google drive response: $response");
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('BACKUP KEY SUCCESS!')),
    );
  }

  bool _isSignedIn() {
    if (_currentUser == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('SIGN IN FIRST!')),
      );
      return false;
    }
    return true;
  }

  _listGoogleDriveFiles() async {
    if (!_isSignedIn()) return;
    String? password = await _askPassword(context);
    if (password == null || password.isEmpty) return;
    final hash = sha256Digest(utf8.encode(password));
    final passwordHash = await _storage.read(key: 'password');
    if (base64Encode(hash) == passwordHash) {
      print("XXXXXX PASSWORD OK");
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('PASSWORD OK!')),
      );
    } else {
      print("XXXXXX PASSWORD FAIL");
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('WRONG PASSWORD!')),
      );
      return;
    }
    print("XXXXXX proceed to restore key from google drive");
    var client = GoogleHttpClient(await _currentUser!.authHeaders);
    var drive = ga.DriveApi(client);
    drive.files.list(spaces: 'appDataFolder').then((value) {
      setState(() {
        list = value;
      });
    });
    var fl = list.files!.length - 1;
    var fName = list.files![fl].name;
    var gdID = list.files![fl].id;
    print("XXXXXX Id: ${list.files![fl].id} File Name:${list.files![fl].name}");
    //   _downloadGoogleDriveFile(list.files![i].name, list.files![i].id);
    ga.Media file = await drive.files
        .get(gdID!, downloadOptions: ga.DownloadOptions.fullMedia) as ga.Media;
    print(file.stream);
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('RESTORE KEY OK!')),
    );
    final directory = await getExternalStorageDirectory();
    print(directory!.path);
    final saveFile = File(
        '${directory.path}/${new DateTime.now().millisecondsSinceEpoch}$fName');
    List<int> dataStore = [];
    file.stream.listen((data) {
      print("XXXXXX DataReceived: ${String.fromCharCodes(data)}");
      // showKeys(String.fromCharCodes(data), String.fromCharCodes(data));

      dataStore.insertAll(dataStore.length, data);
    }, onDone: () {
      print("XXXXXX Task Done");
      saveFile.writeAsBytes(dataStore);
      print("XXXXXX File saved at ${saveFile.path}");
    }, onError: (error) {
      print("XXXXXX Some Error");
    });
    await _storage.write(
        key: 'private_key', value: String.fromCharCodes(dataStore));
    await _storage.write(
        key: 'public_key', value: String.fromCharCodes(dataStore));
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Private key saved securely!')),
    );
  }

  Future<void> _deleteKey() async {
    String? password = await _askPassword(context);
    if (password == null || password.isEmpty) return;
    final passwordHash = sha256Digest(utf8.encode(password));
    await _storage.write(key: 'password', value: base64Encode(passwordHash));
    await _storage.delete(key: 'private_key');
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('DELETED KEY OK!')),
    );
  }

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
    } else {
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
        content:
            SingleChildScrollView(child: Text("$private_key \n $public_key")),
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

  void _backupPrivateKey() async {
    final GoogleSignInAccount? user = _currentUser;
    if (user == null) _handleSignIn();
    final private_key = await _storage.read(key: 'private_key');
    if (private_key == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No key found.')),
      );
      return;
    }
    _uploadFileToGoogleDrive();
    print("XXXXXX private key written to drive");
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
              child:
                  const Text('Generate and Save Private Key in Secure Storage'),
            ),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: _retrieveAndShowKey,
              child: const Text('Retrieve Private Key in Secure Storage'),
            ),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: _deleteKey,
              child: const Text('Delete Private Key from Secure Storage'),
            ),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: _handleSignIn,
              child:
                  const Text('Sign in to Google and consent to Google Drive'),
            ),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: _uploadFileToGoogleDrive,
              child: const Text('Backup Private Key to Google Drive'),
            ),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: _listGoogleDriveFiles,
              child: const Text('Retrieve Private Key from Google Drive'),
            ),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: _handleSignOut,
              child: const Text('Sign out from Google'),
            ),
          ],
        ),
      ),
    );
  }
}
