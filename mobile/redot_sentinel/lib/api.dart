import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:package_info_plus/package_info_plus.dart';

import 'auth_store.dart';
import 'models.dart';

/// Thin client over the /mmwss/api/v1 backend.
///
/// Base URL is compiled in (so the APK always talks to production) but can
/// be overridden at runtime via the build env if you want a dev override.
class Api {
  Api._();
  static final Api instance = Api._();

  // Compile-time override:
  //   flutter build apk --dart-define=MMWSS_BASE=https://example.com/mmwss/api/v1
  static const String _base = String.fromEnvironment(
    'MMWSS_BASE',
    defaultValue: 'https://coldcalling.redotglobal.agency/mmwss/api/v1',
  );

  String get baseUrl => _base;

  Future<Map<String, String>> _headers({bool auth = true}) async {
    final h = <String, String>{
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': await _ua(),
    };
    if (auth) {
      final tok = await AuthStore.instance.readToken();
      if (tok != null) h['Authorization'] = 'Bearer $tok';
    }
    return h;
  }

  static String? _cachedUa;
  Future<String> _ua() async {
    if (_cachedUa != null) return _cachedUa!;
    final info = await PackageInfo.fromPlatform();
    _cachedUa = 'RedotSentinel/${info.version}+${info.buildNumber} (${Platform.operatingSystem})';
    return _cachedUa!;
  }

  Uri _u(String path) => Uri.parse('$_base$path');

  Future<Map<String, dynamic>> _post(String path, Map<String, dynamic> body, {bool auth = true}) async {
    final r = await http.post(_u(path), headers: await _headers(auth: auth), body: jsonEncode(body));
    return _decode(r);
  }

  Future<Map<String, dynamic>> _get(String path) async {
    final r = await http.get(_u(path), headers: await _headers());
    return _decode(r);
  }

  Map<String, dynamic> _decode(http.Response r) {
    final ct = r.headers['content-type'] ?? '';
    if (r.statusCode == 401) throw ApiError(401, 'Session expired — please log in again', kind: 'unauthorized');
    if (r.statusCode >= 400) {
      String msg = 'HTTP ${r.statusCode}';
      try {
        if (ct.contains('application/json')) {
          final j = jsonDecode(r.body) as Map<String, dynamic>;
          msg = (j['detail'] ?? j['message'] ?? msg).toString();
        } else if (r.body.isNotEmpty) {
          msg = r.body;
        }
      } catch (_) {}
      throw ApiError(r.statusCode, msg);
    }
    if (!ct.contains('application/json')) return {};
    return jsonDecode(r.body) as Map<String, dynamic>;
  }

  // ── auth ──

  Future<LoginResult> login({
    required String email, required String password,
    String? deviceLabel, String? appVersion,
  }) async {
    final j = await _post('/login', {
      'email': email,
      'password': password,
      if (deviceLabel != null) 'device_label': deviceLabel,
      if (appVersion != null) 'app_version': appVersion,
    }, auth: false);
    return LoginResult.fromJson(j);
  }

  Future<LoginResult> verify2fa({
    required String pendingToken, required String code,
    String? deviceLabel, String? appVersion,
  }) async {
    final j = await _post('/2fa/verify', {
      'pending_2fa_token': pendingToken,
      'code': code,
      if (deviceLabel != null) 'device_label': deviceLabel,
      if (appVersion != null) 'app_version': appVersion,
    }, auth: false);
    return LoginResult.fromJson(j);
  }

  Future<void> logout() async {
    try { await _post('/logout', {}); } catch (_) {/* ignore */}
  }

  Future<CurrentUser> me() async {
    final j = await _get('/me');
    return CurrentUser.fromJson(j);
  }

  // ── data ──

  Future<DashboardData> dashboard() async {
    final j = await _get('/dashboard');
    return DashboardData.fromJson(j);
  }

  Future<List<Ticket>> tickets({String? status, String? priority}) async {
    final q = <String, String>{};
    if (status != null) q['status_filter'] = status;
    if (priority != null) q['priority'] = priority;
    final qs = q.isEmpty ? '' : '?${q.entries.map((e) => '${e.key}=${Uri.encodeQueryComponent(e.value)}').join('&')}';
    final j = await _get('/tickets$qs');
    return ((j['tickets'] as List?) ?? [])
        .map((e) => Ticket.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  Future<TicketDetail> ticket(int id) async {
    final j = await _get('/tickets/$id');
    return TicketDetail.fromJson(j);
  }

  Future<void> ticketRespond(int id, String? note) async {
    await _post('/tickets/$id/respond', {if (note != null && note.isNotEmpty) 'note': note});
  }

  Future<void> ticketComment(int id, String body) async {
    await _post('/tickets/$id/comment', {'body': body});
  }

  // ── push ──

  Future<void> pushSubscribe({
    required String fcmToken,
    String? deviceLabel,
    String? appVersion,
  }) async {
    await _post('/push/subscribe', {
      'fcm_token': fcmToken,
      'platform': 'android',
      if (deviceLabel != null) 'device_label': deviceLabel,
      if (appVersion != null) 'app_version': appVersion,
    });
  }

  Future<void> pushUnsubscribe(String fcmToken) async {
    await _post('/push/unsubscribe', {'fcm_token': fcmToken});
  }

  Future<int> pushTest() async {
    final j = await _post('/push/test', {});
    return (j['sent'] ?? 0) as int;
  }
}

class ApiError implements Exception {
  final int status;
  final String message;
  final String kind;
  ApiError(this.status, this.message, {this.kind = 'http'});
  @override
  String toString() => message;
}

class LoginResult {
  final String? token;
  final DateTime? expiresAt;
  final CurrentUser? user;
  final String? pending2faToken;
  final bool twoFactorRequired;
  LoginResult({
    required this.token, required this.expiresAt, required this.user,
    required this.pending2faToken, required this.twoFactorRequired,
  });
  factory LoginResult.fromJson(Map<String, dynamic> j) => LoginResult(
    token: j['token'] as String?,
    expiresAt: j['expires_at'] != null ? DateTime.parse(j['expires_at'] as String) : null,
    user: j['user'] != null ? CurrentUser.fromJson(j['user'] as Map<String, dynamic>) : null,
    pending2faToken: j['pending_2fa_token'] as String?,
    twoFactorRequired: (j['two_factor_required'] ?? false) as bool,
  );
}
