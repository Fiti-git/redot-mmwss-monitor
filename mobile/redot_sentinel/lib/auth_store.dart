import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Persists the bearer token + basic user info in encrypted storage
/// (Keystore on Android). Survives app restarts and OS reboots.
class AuthStore {
  AuthStore._();
  static final instance = AuthStore._();

  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static const _kToken = 'bearer_token';
  static const _kEmail = 'user_email';
  static const _kName  = 'user_name';
  static const _kRole  = 'user_role';
  static const _kUid   = 'user_id';

  Future<void> save({
    required String token,
    required int userId,
    required String email,
    required String name,
    required String role,
  }) async {
    await _storage.write(key: _kToken, value: token);
    await _storage.write(key: _kUid,   value: userId.toString());
    await _storage.write(key: _kEmail, value: email);
    await _storage.write(key: _kName,  value: name);
    await _storage.write(key: _kRole,  value: role);
  }

  Future<String?> readToken() => _storage.read(key: _kToken);

  Future<Map<String, String?>> readUser() async {
    return {
      'email': await _storage.read(key: _kEmail),
      'name':  await _storage.read(key: _kName),
      'role':  await _storage.read(key: _kRole),
      'user_id': await _storage.read(key: _kUid),
    };
  }

  Future<void> clear() async {
    await _storage.delete(key: _kToken);
    await _storage.delete(key: _kEmail);
    await _storage.delete(key: _kName);
    await _storage.delete(key: _kRole);
    await _storage.delete(key: _kUid);
  }
}
