#!/bin/bash
set -e

# Define the container image
IMAGE="docker.io/kivy/buildozer"

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

    echo "Installing buildozer and dependencies..."
    pip install --upgrade pip
    # Pin Cython to 0.29.x because pyjnius is not yet fully compatible with Cython 3.x
    pip install buildozer "cython<3.0" sh setuptools

    # Go to work dir
    cd /home/user/hostcwd
    
    # Ensure we don't force a specific SDK path so buildozer can manage it
    sed -i "s|^android.sdk_path =.*|#android.sdk_path =|" buildozer.spec
    sed -i "s|^android.ndk_path =.*|#android.ndk_path =|" buildozer.spec

    echo "Starting Buildozer build..."
    # yes | handles the license prompts
    yes | buildozer android debug
    
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
'