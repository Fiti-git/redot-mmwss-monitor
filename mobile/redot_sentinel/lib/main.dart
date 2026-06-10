import 'package:flutter/material.dart';
import 'package:firebase_core/firebase_core.dart';

import 'theme.dart';
import 'auth_store.dart';
import 'screens/splash.dart';
import 'screens/login.dart';
import 'screens/two_factor.dart';
import 'screens/home_shell.dart';
import 'push.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await Firebase.initializeApp();
  await Push.initBackground();
  runApp(const RedotSentinelApp());
}

class RedotSentinelApp extends StatelessWidget {
  const RedotSentinelApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Redot Sentinel',
      theme: buildRedotTheme(),
      darkTheme: buildRedotTheme(dark: true),
      debugShowCheckedModeBanner: false,
      home: const SplashScreen(),
      routes: {
        '/login': (_) => const LoginScreen(),
        '/2fa': (_) => const TwoFactorScreen(),
        '/home': (_) => const HomeShell(),
      },
    );
  }
}

/// Boot helper — pick the right initial screen based on saved auth state.
Future<Widget> resolveInitialScreen() async {
  final tok = await AuthStore.instance.readToken();
  if (tok == null) return const LoginScreen();
  return const HomeShell();
}
