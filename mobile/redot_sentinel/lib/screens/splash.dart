import 'package:flutter/material.dart';

import '../auth_store.dart';
import '../theme.dart';

class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});
  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen> {
  @override
  void initState() {
    super.initState();
    _route();
  }

  Future<void> _route() async {
    await Future.delayed(const Duration(milliseconds: 350));
    if (!mounted) return;
    final tok = await AuthStore.instance.readToken();
    if (!mounted) return;
    Navigator.of(context).pushReplacementNamed(tok == null ? '/login' : '/home');
  }

  @override
  Widget build(BuildContext context) {
    return const Scaffold(
      backgroundColor: redotRed,
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.shield, size: 96, color: Colors.white),
            SizedBox(height: 24),
            Text('Redot Sentinel',
                style: TextStyle(
                  color: Colors.white, fontSize: 22, fontWeight: FontWeight.w700,
                  letterSpacing: 0.4,
                )),
          ],
        ),
      ),
    );
  }
}
