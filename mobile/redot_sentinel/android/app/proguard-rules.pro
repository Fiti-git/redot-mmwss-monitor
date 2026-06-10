# Flutter / Firebase keep rules.
-keep class io.flutter.** { *; }
-keep class com.google.firebase.** { *; }
-keep class com.google.android.gms.** { *; }
-dontwarn io.flutter.embedding.**
-dontwarn com.google.firebase.**

# flutter_local_notifications uses reflection
-keep class com.dexterous.flutterlocalnotifications.** { *; }
