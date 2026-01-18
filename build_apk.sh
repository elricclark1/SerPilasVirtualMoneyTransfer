#!/bin/bash
set -e

# Use the same image used by the successful GitHub Actions workflows
IMAGE="ghcr.io/kivy/buildozer:latest"

# Ensure directories exist locally
mkdir -p bin
mkdir -p .buildozer_container

echo "Starting Buildozer with GitHub Container..."
# Mount local .buildozer_container to /root/.buildozer for persistence
# We use -i to pass the heredoc to the container
podman run --rm -i \
    --entrypoint /bin/bash \
    -v "$(pwd):/home/user/hostcwd:Z" \
    -v "$(pwd)/.buildozer_container:/root/.buildozer:Z" \
    -w /home/user/hostcwd \
    -e BUILDOZER_WARN_ON_ROOT=0 \
    $IMAGE <<'EOF'
set -e
echo 'Preparing Android SDK Tools...'
mkdir -p /root/.buildozer/android/platform

# Run prep to get tools
yes | buildozer android debug --prep || true

SDK_ROOT='/root/.buildozer/android/platform/android-sdk'
if [ -f "$SDK_ROOT/tools/bin/sdkmanager" ]; then
    echo "Installing Android API 33 components..."
    yes | "$SDK_ROOT/tools/bin/sdkmanager" --sdk_root="$SDK_ROOT" "platforms;android-33" "build-tools;33.0.0" "platform-tools"
fi

echo "Starting Build..."
export LDFLAGS=' '
buildozer android debug
EOF

# Find artifact
LATEST_APK=$(ls -t bin/*.apk 2>/dev/null | head -n1)
if [ -n "$LATEST_APK" ]; then
    ABS_APK=$(realpath "$LATEST_APK")
    echo "--------------------------------------------------------"
    echo "SUCCESS! APK is ready at: $LATEST_APK"
    echo "FULL PATH (for LocalSend): $ABS_APK"
    echo "--------------------------------------------------------"
else
    echo "ERROR: Build finished but no APK found."
    exit 1
fi