import 'dart:io';

import 'package:flutter/material.dart' show Color;
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:package_info_plus/package_info_plus.dart';

import 'api.dart';

/// FCM glue.
///
/// Channel: redot_sentinel_alerts (matches the channel_id the backend
/// includes in messaging.AndroidConfig). High importance → heads-up
/// notification when in foreground.
class Push {
  static const channelId = 'redot_sentinel_alerts';
  static const channelName = 'Redot Sentinel alerts';
  static const channelDesc = 'P1 tickets, scanner critical findings, honeytoken breaches.';

  static final _local = FlutterLocalNotificationsPlugin();
  static String? _lastToken;

  /// Called from main() at app boot. Sets up the background isolate handler
  /// + the local notifications channel.
  static Future<void> initBackground() async {
    FirebaseMessaging.onBackgroundMessage(_backgroundHandler);
    await _ensureLocalChannel();
  }

  static Future<void> _ensureLocalChannel() async {
    const androidInit = AndroidInitializationSettings('@mipmap/ic_launcher');
    await _local.initialize(const InitializationSettings(android: androidInit));
    final androidImpl = _local.resolvePlatformSpecificImplementation<
        AndroidFlutterLocalNotificationsPlugin>();
    await androidImpl?.createNotificationChannel(const AndroidNotificationChannel(
      channelId, channelName,
      description: channelDesc,
      importance: Importance.high,
    ));
  }

  /// Call this from the post-login flow. Requests permission, fetches the
  /// FCM token, registers it with the backend, and wires foreground handlers.
  static Future<void> registerForUser() async {
    final fm = FirebaseMessaging.instance;
    await fm.requestPermission(alert: true, badge: true, sound: true);

    await fm.setForegroundNotificationPresentationOptions(
      alert: true, badge: true, sound: true,
    );

    final token = await fm.getToken();
    if (token == null) return;
    _lastToken = token;

    final info = await PackageInfo.fromPlatform();
    final deviceLabel = Platform.operatingSystem == 'android'
        ? 'Android ${Platform.operatingSystemVersion}'
        : Platform.operatingSystem;
    try {
      await Api.instance.pushSubscribe(
        fcmToken: token,
        deviceLabel: deviceLabel,
        appVersion: '${info.version}+${info.buildNumber}',
      );
    } catch (_) {/* swallow — retry on next launch */}

    fm.onTokenRefresh.listen((t) async {
      _lastToken = t;
      try {
        await Api.instance.pushSubscribe(
          fcmToken: t, deviceLabel: deviceLabel,
          appVersion: '${info.version}+${info.buildNumber}',
        );
      } catch (_) {}
    });

    FirebaseMessaging.onMessage.listen(_showForegroundNotification);
  }

  static Future<void> unregister() async {
    if (_lastToken == null) return;
    try { await Api.instance.pushUnsubscribe(_lastToken!); } catch (_) {}
    _lastToken = null;
  }

  static Future<void> _showForegroundNotification(RemoteMessage msg) async {
    final n = msg.notification;
    if (n == null) return;
    await _local.show(
      msg.hashCode,
      n.title ?? 'Redot Sentinel',
      n.body ?? '',
      NotificationDetails(
        android: AndroidNotificationDetails(
          channelId, channelName,
          channelDescription: channelDesc,
          importance: Importance.high,
          priority: Priority.high,
          color: const Color(0xFFE11E27),
          ticker: n.title,
        ),
      ),
      payload: msg.data.toString(),
    );
  }
}

/// Top-level — required by FCM for background message handling.
@pragma('vm:entry-point')
Future<void> _backgroundHandler(RemoteMessage message) async {
  await Firebase.initializeApp();
  // System tray notification is shown by FCM itself; we just need this hook
  // to exist so the plugin doesn't drop the message.
}

