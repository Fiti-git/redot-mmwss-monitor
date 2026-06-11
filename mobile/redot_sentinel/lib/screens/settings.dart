import 'package:flutter/material.dart';
import 'package:package_info_plus/package_info_plus.dart';

import '../api.dart';
import '../auth_store.dart';
import '../models.dart';
import '../push.dart';
import '../theme.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});
  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  String? _email;
  String? _name;
  String? _role;
  String? _version;
  String? _fcmToken;
  PushPreferences? _prefs;
  bool _loadingPrefs = true;
  String? _prefsError;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final u = await AuthStore.instance.readUser();
    final p = await PackageInfo.fromPlatform();
    if (!mounted) return;
    setState(() {
      _email = u['email'];
      _name = u['name'];
      _role = u['role'];
      _version = '${p.version} (build ${p.buildNumber})';
    });
    await _loadPrefs();
  }

  Future<void> _loadPrefs() async {
    setState(() { _loadingPrefs = true; _prefsError = null; });
    try {
      final tok = await Push.getToken();
      if (tok == null) {
        setState(() {
          _loadingPrefs = false;
          _prefsError = 'No FCM token yet — grant notification permission';
        });
        return;
      }
      _fcmToken = tok;
      final prefs = await Api.instance.pushPreferencesGet(tok);
      if (!mounted) return;
      setState(() { _prefs = prefs; _loadingPrefs = false; });
    } on ApiError catch (e) {
      if (!mounted) return;
      setState(() { _loadingPrefs = false; _prefsError = e.message; });
    } catch (e) {
      if (!mounted) return;
      setState(() { _loadingPrefs = false; _prefsError = 'Network error'; });
    }
  }

  Future<void> _updatePref(String kind, bool value) async {
    if (_fcmToken == null || _prefs == null) return;
    // Optimistic update
    setState(() {
      switch (kind) {
        case 'p1':       _prefs!.notifyP1 = value; break;
        case 'scanner':  _prefs!.notifyScannerCritical = value; break;
        case 'honey':    _prefs!.notifyHoneytoken = value; break;
        case 'report':   _prefs!.notifyReportReady = value; break;
        case 'sla':      _prefs!.notifySlaWarning = value; break;
      }
    });
    try {
      await Api.instance.pushPreferencesSet(
        fcmToken: _fcmToken!,
        notifyP1: kind == 'p1' ? value : null,
        notifyScannerCritical: kind == 'scanner' ? value : null,
        notifyHoneytoken: kind == 'honey' ? value : null,
        notifyReportReady: kind == 'report' ? value : null,
        notifySlaWarning: kind == 'sla' ? value : null,
      );
    } on ApiError catch (e) {
      _snack(e.message);
      _loadPrefs(); // revert by reloading
    }
  }

  Future<void> _testPush() async {
    try {
      final n = await Api.instance.pushTest();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Test push sent to $n device${n == 1 ? '' : 's'}')),
      );
    } on ApiError catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(e.message)));
    }
  }

  Future<void> _logout() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Sign out?'),
        content: const Text('You will need to sign in again next time.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          TextButton(onPressed: () => Navigator.pop(context, true),
              child: const Text('Sign out', style: TextStyle(color: redotRed))),
        ],
      ),
    );
    if (ok != true) return;
    await Push.unregister();
    await Api.instance.logout();
    await AuthStore.instance.clear();
    if (!mounted) return;
    Navigator.of(context).pushNamedAndRemoveUntil('/login', (_) => false);
  }

  void _snack(String m) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(m)));
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 24),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              if (_name != null) Text(_name!, style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w700)),
              if (_email != null) Padding(
                padding: const EdgeInsets.only(top: 2),
                child: Text(_email!, style: const TextStyle(color: redotMuted)),
              ),
              if (_role != null) Padding(
                padding: const EdgeInsets.only(top: 6),
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                  decoration: BoxDecoration(
                    color: redotRed.withOpacity(0.12),
                    borderRadius: BorderRadius.circular(20),
                  ),
                  child: Text(_role!, style: const TextStyle(color: redotRed, fontWeight: FontWeight.w600, fontSize: 12)),
                ),
              ),
            ]),
          ),
        ),
        const SizedBox(height: 16),
        _section('NOTIFICATIONS'),
        if (_loadingPrefs)
          const Padding(
            padding: EdgeInsets.symmetric(vertical: 24),
            child: Center(child: CircularProgressIndicator(color: redotRed)),
          )
        else if (_prefsError != null)
          Card(
            child: ListTile(
              leading: const Icon(Icons.error_outline, color: redotRed),
              title: Text(_prefsError!, style: const TextStyle(color: redotMuted)),
              trailing: IconButton(icon: const Icon(Icons.refresh), onPressed: _loadPrefs),
            ),
          )
        else if (_prefs != null)
          Card(
            child: Column(children: [
              _prefTile('P1 tickets', 'New P1 ticket created',
                  _prefs!.notifyP1, (v) => _updatePref('p1', v), Icons.priority_high),
              const Divider(height: 0),
              _prefTile('Scanner critical', 'Critical vulnerability found',
                  _prefs!.notifyScannerCritical, (v) => _updatePref('scanner', v), Icons.shield),
              const Divider(height: 0),
              _prefTile('Honeytoken breach', 'Fake credential was used',
                  _prefs!.notifyHoneytoken, (v) => _updatePref('honey', v), Icons.bug_report),
              const Divider(height: 0),
              _prefTile('Report ready', 'Monthly / weekly report generated',
                  _prefs!.notifyReportReady, (v) => _updatePref('report', v), Icons.description),
              const Divider(height: 0),
              _prefTile('SLA warning', 'Ticket SLA close to breach',
                  _prefs!.notifySlaWarning, (v) => _updatePref('sla', v), Icons.timer),
            ]),
          ),
        const SizedBox(height: 16),
        Card(
          child: Column(children: [
            ListTile(
              leading: const Icon(Icons.notifications_active, color: redotRed),
              title: const Text('Send test push'),
              subtitle: const Text('Verify this phone receives alerts'),
              onTap: _testPush,
            ),
            const Divider(height: 0),
            ListTile(
              leading: const Icon(Icons.logout, color: redotRed),
              title: const Text('Sign out'),
              onTap: _logout,
            ),
          ]),
        ),
        const SizedBox(height: 24),
        Center(
          child: Column(children: [
            const Icon(Icons.shield, size: 28, color: redotMuted),
            const SizedBox(height: 4),
            Text('Redot Sentinel ${_version ?? ''}',
                style: const TextStyle(color: redotMuted, fontSize: 12)),
            const SizedBox(height: 4),
            const Text('© Redot Global', style: TextStyle(color: redotMuted, fontSize: 11)),
          ]),
        ),
      ],
    );
  }

  Widget _section(String s) => Padding(
    padding: const EdgeInsets.fromLTRB(4, 8, 4, 8),
    child: Text(s, style: const TextStyle(
        letterSpacing: 1.2, fontSize: 11, color: redotMuted, fontWeight: FontWeight.w700)),
  );

  Widget _prefTile(String title, String subtitle, bool value,
      ValueChanged<bool> onChanged, IconData icon) {
    return SwitchListTile(
      value: value,
      onChanged: onChanged,
      secondary: Icon(icon, color: redotRed),
      title: Text(title, style: const TextStyle(fontWeight: FontWeight.w600)),
      subtitle: Text(subtitle, style: const TextStyle(fontSize: 12, color: redotMuted)),
      activeColor: redotRed,
    );
  }
}
