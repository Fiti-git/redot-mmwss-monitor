import 'package:flutter/material.dart';

const Color redotRed = Color(0xFFE11E27);
const Color redotInk = Color(0xFF12131A);
const Color redotMuted = Color(0xFF6B7280);
const Color redotBg = Color(0xFFF7F7F8);

ThemeData buildRedotTheme({bool dark = false}) {
  final scheme = ColorScheme.fromSeed(
    seedColor: redotRed,
    brightness: dark ? Brightness.dark : Brightness.light,
  );
  return ThemeData(
    colorScheme: scheme,
    useMaterial3: true,
    scaffoldBackgroundColor: dark ? null : redotBg,
    appBarTheme: AppBarTheme(
      centerTitle: false,
      backgroundColor: dark ? null : Colors.white,
      foregroundColor: redotInk,
      elevation: 0,
      titleTextStyle: const TextStyle(
        fontSize: 18, fontWeight: FontWeight.w700, color: redotInk,
      ),
    ),
    elevatedButtonTheme: ElevatedButtonThemeData(
      style: ElevatedButton.styleFrom(
        backgroundColor: redotRed,
        foregroundColor: Colors.white,
        minimumSize: const Size.fromHeight(48),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
        textStyle: const TextStyle(fontWeight: FontWeight.w600),
      ),
    ),
    textButtonTheme: TextButtonThemeData(
      style: TextButton.styleFrom(foregroundColor: redotRed),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: dark ? Colors.white10 : Colors.white,
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(10),
        borderSide: BorderSide(color: Colors.grey.shade300),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(10),
        borderSide: BorderSide(color: Colors.grey.shade300),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(10),
        borderSide: const BorderSide(color: redotRed, width: 1.6),
      ),
    ),
    cardTheme: CardThemeData(
      color: dark ? null : Colors.white,
      elevation: 0,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      margin: const EdgeInsets.symmetric(vertical: 6, horizontal: 0),
    ),
  );
}

// Severity / priority colors
Color priorityColor(String p) {
  switch (p) {
    case 'p1': return const Color(0xFFE11E27);
    case 'p2': return const Color(0xFFF59E0B);
    case 'p3': return const Color(0xFF3B82F6);
    default:   return const Color(0xFF6B7280);
  }
}

Color slaColor(String state) {
  switch (state) {
    case 'breached': return const Color(0xFFE11E27);
    case 'met':      return const Color(0xFF10B981);
    default:         return const Color(0xFFF59E0B);
  }
}
