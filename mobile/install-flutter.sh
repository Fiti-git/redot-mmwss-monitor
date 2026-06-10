#!/usr/bin/env bash
# One-time install of Flutter SDK + Android SDK + JDK 17 on callora.
# Idempotent — re-running is safe.
#
# Disk footprint: ~3 GB. The c6g.medium VPS has enough.
set -euo pipefail

FLUTTER_VERSION="3.24.5"
FLUTTER_DIR="/opt/flutter"
ANDROID_DIR="/opt/android-sdk"
JDK_PKG="openjdk-17-jdk-headless"

echo "==> Installing system deps"
sudo apt-get update -qq
sudo apt-get install -y -qq \
    curl unzip xz-utils zip \
    git wget \
    libglu1-mesa \
    "$JDK_PKG"

# ── Flutter ──
if [ ! -d "$FLUTTER_DIR" ]; then
    echo "==> Downloading Flutter $FLUTTER_VERSION"
    cd /tmp
    URL="https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_${FLUTTER_VERSION}-stable.tar.xz"
    curl -fLO "$URL"
    sudo mkdir -p "$FLUTTER_DIR"
    sudo tar -xJf "flutter_linux_${FLUTTER_VERSION}-stable.tar.xz" -C /opt
    rm -f "flutter_linux_${FLUTTER_VERSION}-stable.tar.xz"
    # /opt/flutter is the extracted dir already
fi

# ── Android command-line tools ──
if [ ! -d "$ANDROID_DIR/cmdline-tools/latest" ]; then
    echo "==> Downloading Android command-line tools"
    cd /tmp
    URL="https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
    curl -fLO "$URL"
    sudo mkdir -p "$ANDROID_DIR/cmdline-tools"
    sudo unzip -q -o commandlinetools-linux-*.zip -d "$ANDROID_DIR/cmdline-tools"
    sudo mv "$ANDROID_DIR/cmdline-tools/cmdline-tools" "$ANDROID_DIR/cmdline-tools/latest"
    rm -f commandlinetools-linux-*.zip
fi

# ── Global PATH for all logins ──
PROFILE="/etc/profile.d/flutter.sh"
sudo tee "$PROFILE" >/dev/null <<EOF
export PATH="\$PATH:${FLUTTER_DIR}/bin"
export ANDROID_HOME="${ANDROID_DIR}"
export ANDROID_SDK_ROOT="${ANDROID_DIR}"
export PATH="\$PATH:${ANDROID_DIR}/cmdline-tools/latest/bin:${ANDROID_DIR}/platform-tools"
export JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"
EOF
. "$PROFILE"

# ── Permissions: make Flutter writable so the user can run pub get etc. ──
sudo chown -R "$USER":"$USER" "$FLUTTER_DIR" "$ANDROID_DIR"

# ── Accept Android licences + install SDKs ──
echo "==> Accepting Android SDK licences"
yes | sdkmanager --licenses >/dev/null

echo "==> Installing SDK platforms + build-tools"
sdkmanager --install \
    "platform-tools" \
    "platforms;android-34" \
    "build-tools;34.0.0"

# ── Flutter sanity check ──
flutter --disable-analytics
flutter precache --android
flutter doctor -v || true

echo
echo "════════════════════════════════════════════════════════════════"
echo "  ✓ Flutter + Android SDK installed."
echo "  Open a NEW shell (or source /etc/profile.d/flutter.sh) and run:"
echo "    cd /srv/mmwss/repo/mobile/redot_sentinel && bash bootstrap.sh"
echo "════════════════════════════════════════════════════════════════"
