#!/usr/bin/env bash
# Bootstrap + build the Redot Sentinel APK from scratch on callora.
#
# Prereqs (one-time): see ../README-build.md
#   sudo bash /srv/mmwss/repo/mobile/install-flutter.sh
#
# Subsequent builds: just `bash bootstrap.sh`.
# Output: /srv/mmwss/repo/app/static/downloads/redot-sentinel.apk
set -euo pipefail

cd "$(dirname "$0")"
HERE="$(pwd)"
REPO_ROOT="$(cd ../.. && pwd)"

# ── 0. sanity ──
command -v flutter >/dev/null || { echo "✗ flutter not on PATH — run install-flutter.sh first"; exit 1; }
flutter --version | head -1

# ── 1. google-services.json ──
GSJ="android/app/google-services.json"
if [ ! -f "$GSJ" ]; then
    echo "✗ Missing $GSJ"
    echo "  Drop the Firebase Android-client config (project mmwss-notifications,"
    echo "  package com.redot.mmwss) at $HERE/$GSJ and re-run."
    exit 1
fi

# ── 2. Keystore (one-time, persisted in /srv/mmwss/secrets) ──
KEYSTORE_DIR="/srv/mmwss/secrets"
KEYSTORE_PATH="${KEYSTORE_DIR}/redot-sentinel-upload.jks"
sudo mkdir -p "$KEYSTORE_DIR"
sudo chmod 700 "$KEYSTORE_DIR"

if ! sudo test -f "$KEYSTORE_PATH"; then
    echo "==> Generating release keystore at $KEYSTORE_PATH"
    PW="$(openssl rand -base64 24 | tr -d '/+=')"
    sudo keytool -genkey -v -keystore "$KEYSTORE_PATH" \
        -keyalg RSA -keysize 2048 -validity 36500 \
        -alias redot-sentinel \
        -storepass "$PW" -keypass "$PW" \
        -dname "CN=Redot Sentinel, OU=MMWSS, O=Redot Global, L=Singapore, S=SG, C=SG"
    echo "$PW" | sudo tee "${KEYSTORE_DIR}/redot-sentinel-keystore.pw" >/dev/null
    sudo chmod 600 "$KEYSTORE_PATH" "${KEYSTORE_DIR}/redot-sentinel-keystore.pw"
    echo "==> Keystore created. Password stored at ${KEYSTORE_DIR}/redot-sentinel-keystore.pw"
fi

# Copy keystore + write key.properties for this build
cp -f "$KEYSTORE_PATH" android/app/upload-keystore.jks
PW="$(sudo cat ${KEYSTORE_DIR}/redot-sentinel-keystore.pw)"
cat > android/key.properties <<EOF
storePassword=${PW}
keyPassword=${PW}
keyAlias=redot-sentinel
storeFile=upload-keystore.jks
EOF
chmod 600 android/key.properties android/app/upload-keystore.jks

# ── 3. Generate the rest of the Flutter scaffold (gradle wrapper etc.) ──
# `flutter create .` is destructive to files it already manages; it leaves
# our lib/ and android/app/src/main/ overlay alone if they already exist.
if [ ! -f android/gradlew ]; then
    echo "==> Scaffolding gradle wrapper (first run only)"
    # Bring in only what's missing — preserves our overlay files.
    flutter create --org com.redot --project-name redot_sentinel \
        --platforms android --description "Redot Sentinel — MMWSS monitoring" \
        --no-overwrite .
fi

# ── 4. Deps + icons ──
flutter pub get
echo "==> Generating launcher icons from assets/redot-icon.png"
dart run flutter_launcher_icons || echo "  (skipped — non-fatal)"

# ── 5. Build the APK ──
echo "==> Building release APK"
flutter build apk --release --shrink

# ── 6. Publish to /mmwss/app/download ──
DOWNLOAD_DIR="${REPO_ROOT}/app/static/downloads"
mkdir -p "$DOWNLOAD_DIR"
APK_SRC="build/app/outputs/flutter-apk/app-release.apk"
APK_DST="${DOWNLOAD_DIR}/redot-sentinel.apk"

cp -f "$APK_SRC" "$APK_DST"

# Record version + sha for the download page
VERSION="$(grep '^version:' pubspec.yaml | awk '{print $2}')"
SHA="$(sha256sum "$APK_DST" | awk '{print $1}')"
SIZE="$(stat --format='%s' "$APK_DST")"
cat > "${DOWNLOAD_DIR}/redot-sentinel.json" <<EOF
{
  "version": "${VERSION}",
  "sha256": "${SHA}",
  "size_bytes": ${SIZE},
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

echo
echo "════════════════════════════════════════════════════════════════"
echo "  ✓ APK built and published"
echo "    File:    $APK_DST"
echo "    Version: $VERSION"
echo "    SHA256:  $SHA"
echo "    Size:    $(numfmt --to=iec --suffix=B $SIZE 2>/dev/null || echo $SIZE)"
echo
echo "  Install from the admin team's phone:"
echo "    https://coldcalling.redotglobal.agency/mmwss/app/download"
echo "════════════════════════════════════════════════════════════════"
