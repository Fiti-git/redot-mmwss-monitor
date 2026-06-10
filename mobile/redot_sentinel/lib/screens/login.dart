import 'dart:io';

import 'package:flutter/material.dart';
import 'package:package_info_plus/package_info_plus.dart';

import '../api.dart';
import '../auth_store.dart';
import '../push.dart';
import '../theme.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});
  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _email = TextEditingController();
  final _password = TextEditingController();
  final _formKey = GlobalKey<FormState>();
  bool _loading = false;
  String? _error;

  @override
  void dispose() {
    _email.dispose();
    _password.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() { _loading = true; _error = null; });
    try {
      final info = await PackageInfo.fromPlatform();
      final res = await Api.instance.login(
        email: _email.text.trim(),
        password: _password.text,
        deviceLabel: 'Android ${Platform.operatingSystemVersion}',
        appVersion: '${info.version}+${info.buildNumber}',
      );
      if (!mounted) return;

      if (res.twoFactorRequired) {
        Navigator.of(context).pushReplacementNamed('/2fa', arguments: res.pending2faToken);
        return;
      }
      if (res.token == null || res.user == null) {
        setState(() => _error = 'Unexpected response from server');
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
    } catch (e) {
      setState(() => _error = 'Network error — check your connection');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.symmetric(horizontal: 28, vertical: 32),
            child: Form(
              key: _formKey,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const SizedBox(height: 24),
                  Container(
                    width: 72, height: 72,
                    decoration: BoxDecoration(
                      color: redotRed,
                      borderRadius: BorderRadius.circular(16),
                    ),
                    child: const Icon(Icons.shield, color: Colors.white, size: 40),
                  ),
                  const SizedBox(height: 20),
                  const Text('Redot Sentinel',
                      style: TextStyle(fontSize: 24, fontWeight: FontWeight.w700, color: redotInk)),
                  const SizedBox(height: 4),
                  const Text('Sign in to MMWSS',
                      style: TextStyle(color: redotMuted)),
                  const SizedBox(height: 32),
                  TextFormField(
                    controller: _email,
                    decoration: const InputDecoration(
                      labelText: 'Email',
                      prefixIcon: Icon(Icons.email_outlined),
                    ),
                    keyboardType: TextInputType.emailAddress,
                    autocorrect: false,
                    textInputAction: TextInputAction.next,
                    validator: (v) =>
                        (v == null || !v.contains('@')) ? 'Enter a valid email' : null,
                  ),
                  const SizedBox(height: 12),
                  TextFormField(
                    controller: _password,
                    decoration: const InputDecoration(
                      labelText: 'Password',
                      prefixIcon: Icon(Icons.lock_outline),
                    ),
                    obscureText: true,
                    textInputAction: TextInputAction.done,
                    onFieldSubmitted: (_) => _submit(),
                    validator: (v) =>
                        (v == null || v.isEmpty) ? 'Enter your password' : null,
                  ),
                  const SizedBox(height: 20),
                  if (_error != null) ...[
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: redotRed.withOpacity(0.08),
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: redotRed.withOpacity(0.4)),
                      ),
                      child: Row(children: [
                        const Icon(Icons.error_outline, color: redotRed, size: 18),
                        const SizedBox(width: 8),
                        Expanded(child: Text(_error!, style: const TextStyle(color: redotRed))),
                      ]),
                    ),
                    const SizedBox(height: 16),
                  ],
                  ElevatedButton(
                    onPressed: _loading ? null : _submit,
                    child: _loading
                        ? const SizedBox(
                            width: 22, height: 22,
                            child: CircularProgressIndicator(
                                strokeWidth: 2.4, color: Colors.white),
                          )
                        : const Text('Sign in'),
                  ),
                  const SizedBox(height: 16),
                  const Text(
                    'For Redot Global internal team only.',
                    textAlign: TextAlign.center,
                    style: TextStyle(color: redotMuted, fontSize: 12),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
