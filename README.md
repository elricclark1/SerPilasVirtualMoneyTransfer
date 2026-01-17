# Serpilas Virtual Money Transfer

A local network virtual money transfer system built with Flask and Kivy.
Designed to be a Monopoly banking assistant or a local economy simulator.

## Project Structure

- **main.py**: The entry point. Runs the Kivy GUI and starts the Flask server in a background thread.
- **app.py**: The Flask application logic (routes, database models).
- **buildozer.spec**: Configuration for building the Android APK using Buildozer.

## Local Development (PC/Linux)

1.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run the App:**
    ```bash
    python main.py
    ```
    This will open a window showing the QR code for the server.
    Open the displayed URL (e.g., `http://192.168.1.X:8080`) on any device on the same Wi-Fi.

## Building for Android

Ensure you have `buildozer` installed (`pip install buildozer`).

```bash
buildozer android debug
```

## Admin Access

- **Login URL:** `/admin`
- **Default Password:** `ADMIN123`
