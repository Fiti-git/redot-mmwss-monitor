import 'package:flutter/material.dart';
import 'package:package_info_plus/package_info_plus.dart';

import '../api.dart';
import '../auth_store.dart';
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

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 24),
      children: [
        const Text('Settings', style: TextStyle(fontSize: 22, fontWeight: FontWeight.w700)),
        const SizedBox(height: 16),
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
}
