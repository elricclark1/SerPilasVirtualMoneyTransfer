#!/bin/bash
set -e

# Define the container image
IMAGE="kivy/buildozer"

# Ensure the bin directory exists locally
mkdir -p bin

echo "Starting Buildozer Container..."
# Use :Z for shared volume mount on Fedora
podman run --rm --userns=keep-id --entrypoint /bin/bash -v "$(pwd):/home/user/hostcwd:Z" $IMAGE -c '
    set -e
    
    # Create a fresh virtual environment
    echo "Creating local build environment..."
    python3 -m venv ~/build_venv
    source ~/build_venv/bin/activate

    echo "Installing buildozer..."
    pip install --upgrade pip
    # Pin Cython to 0.29.x because pyjnius is not yet fully compatible with Cython 3.x
    pip install buildozer "cython<3.0" sh setuptools

    # Pre-setup SDK
    export ANDROID_HOME="/home/ubuntu/.buildozer/android/platform/android-sdk"
    mkdir -p $ANDROID_HOME/cmdline-tools

    if [ ! -d "$ANDROID_HOME/cmdline-tools/latest" ]; then
        echo "Downloading Android Command Line Tools..."
        cd $ANDROID_HOME/cmdline-tools
        python3 -c "import urllib.request; urllib.request.urlretrieve(\"https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip\", \"tools.zip\")"
        unzip -q tools.zip
        mv cmdline-tools latest
        rm tools.zip
    fi

    export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"

    echo "Pre-installing Android API 33..."
    yes | sdkmanager --sdk_root=$ANDROID_HOME "platforms;android-33" "build-tools;33.0.0" "platform-tools"

    # Go to work dir
    cd /home/user/hostcwd
    
    # Ensure buildozer uses the right SDK path
    sed -i "s|^#android.sdk_path =.*|android.sdk_path = /home/ubuntu/.buildozer/android/platform/android-sdk|" buildozer.spec

    echo "Starting Buildozer build..."
    yes | buildozer android debug
    
    # Find and rename artifact
    LATEST_APK=$(ls -t bin/*.apk | grep -v "SerPilasViritualMoneyTrasferv1.2.apk" | head -n1)
    if [ -n "$LATEST_APK" ]; then
        TARGET="bin/SerPilasViritualMoneyTrasferv1.2.apk"
        cp "$LATEST_APK" "$TARGET"
        echo "--------------------------------------------------------"
        echo "SUCCESS! APK is ready at: $TARGET"
        echo "--------------------------------------------------------"
    else
        echo "ERROR: Build finished but no APK found."
        exit 1
    fi
'