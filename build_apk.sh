#!/bin/bash
set -e

# Define the container image
IMAGE="kivy/buildozer"

# Run the build inside the container
# Added :Z to volume mounts for SELinux relabeling
podman run --rm --entrypoint /bin/bash -v "$(pwd):/home/user/hostcwd:Z" $IMAGE -c '
    set -e
    
    # 3. Install missing SDK components manually
    # Note: Buildozer will install SDK in the project directory now (.buildozer)
    # We need to locate it correctly if we want to patch it, but usually buildozer handles it.
    # For now, let's trust buildozer to init it in ./.buildozer
    
    echo "Starting Buildozer..."
    cd /home/user/hostcwd
    yes | buildozer android debug
    
    # Rename the output to the desired friendly name
    # Buildozer puts it in bin/
    # We anticipate the file pattern: serpilas_transfer-1.0-arm64-v8a-debug.apk
    
    cp bin/*-debug.apk bin/SerPilasViritualMoneyTrasferv1.2.apk
    echo "Build Complete. APK available at bin/SerPilasViritualMoneyTrasferv1.2.apk"
'