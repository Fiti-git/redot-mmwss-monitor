import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:package_info_plus/package_info_plus.dart';

import '../api.dart';
import '../auth_store.dart';
import '../push.dart';
import '../theme.dart';

class TwoFactorScreen extends StatefulWidget {
  const TwoFactorScreen({super.key});
  @override
  State<TwoFactorScreen> createState() => _TwoFactorScreenState();
}

class _TwoFactorScreenState extends State<TwoFactorScreen> {
  final _code = TextEditingController();
  bool _loading = false;
  String? _error;
  String? _pendingToken;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _pendingToken ??= ModalRoute.of(context)?.settings.arguments as String?;
  }

  @override
  void dispose() {
    _code.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (_pendingToken == null) {
      Navigator.of(context).pushReplacementNamed('/login');
      return;
    }
    final code = _code.text.trim();
    if (code.length < 6) {
      setState(() => _error = 'Enter the 6-digit code');
      return;
    }
    setState(() { _loading = true; _error = null; });
    try {
      final info = await PackageInfo.fromPlatform();
      final res = await Api.instance.verify2fa(
        pendingToken: _pendingToken!,
        code: code,
        deviceLabel: 'Android ${Platform.operatingSystemVersion}',
        appVersion: '${info.version}+${info.buildNumber}',
      );
      if (res.token == null || res.user == null) {
        setState(() => _error = 'Unexpected response');
        return;
      }
      await AuthStore.instance.save(
        token: res.token!, userId: res.user!.id,
        email: res.user!.email, name: res.user!.name, role: res.user!.role,
      );
      await Push.registerForUser();
      if (!mounted) return;
      Navigator.of(context).pushReplacementNamed('/home');
    } on ApiError catch (e) {
      setState(() => _error = e.message);
    } catch (_) {
      setState(() => _error = 'Network error');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Two-factor auth')),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 28, vertical: 24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Icon(Icons.lock_clock, size: 56, color: redotRed),
              const SizedBox(height: 16),
              const Text('Enter the 6-digit code from your authenticator app',
                  textAlign: TextAlign.center,
                  style: TextStyle(fontWeight: FontWeight.w600)),
              const SizedBox(height: 24),
              TextField(
                controller: _code,
                keyboardType: TextInputType.number,
                textAlign: TextAlign.center,
                autofocus: true,
                style: const TextStyle(fontSize: 24, letterSpacing: 6, fontWeight: FontWeight.w700),
                maxLength: 8,
                inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                decoration: const InputDecoration(
                  counterText: '',
                  hintText: '000000',
                ),
                onSubmitted: (_) => _submit(),
              ),
              const SizedBox(height: 20),
              if (_error != null) ...[
                Text(_error!, style: const TextStyle(color: redotRed), textAlign: TextAlign.center),
                const SizedBox(height: 16),
              ],
              ElevatedButton(
                onPressed: _loading ? null : _submit,
                child: _loading
                    ? const SizedBox(
                        width: 22, height: 22,
                        child: CircularProgressIndicator(strokeWidth: 2.4, color: Colors.white),
                      )
                    : const Text('Verify'),
              ),
              const SizedBox(height: 12),
              TextButton(
                onPressed: () => Navigator.of(context).pushReplacementNamed('/login'),
                child: const Text('Back to sign-in'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
