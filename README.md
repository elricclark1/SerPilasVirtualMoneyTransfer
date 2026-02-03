# SerPilas Virtual Money

A local network virtual money transfer system designed to digitize banking for games like Monopoly. This project allows one computer to act as the "Central Bank" while other players join using their own phones via a web browser.

---

## 🚀 Desktop Hosting (Windows, Mac, Linux)

Running the server from your computer is the easiest way to play!

### 1. Download & Prepare
Download the repository and unzip it.

### 2. Launch the Server
*   **Windows:** Double-click `run_windows.bat`.
*   **Linux/Mac:** Open a terminal in the folder and run `./run_unix.sh`.

*The script will automatically set up a virtual environment, install requirements, and start the app.*

### 3. Connect Players
1.  A window will appear on your desktop showing a **QR Code** and an **IP Address**.
2.  All players must be on the **same Wi-Fi** network.
3.  Players scan the QR code with their phones to open the game dashboard.
4.  The Host (you) will automatically have a browser tab open to the Admin Dashboard.

---

## 🛠️ Tech Stack

- **Backend:** Flask (Python)
- **Database:** SQLite (SQLAlchemy)
- **Host UI:** Kivy
- **Frontend:** HTML5 / Tailwind CSS (Serve via Flask)

## 👤 Admin Features

The host has special "Root" privileges:
- **Mint/Burn:** Create money out of thin air or destroy it.
- **Banker Mode:** Move money between any two players.
- **Permissions:** Grant other players "Banker" status.
- **Export/Import:** Save your game state to a JSON file and resume later.

---
*Vibe coded by Elric. Visit [serpilas.com](https://serpilas.com/) for more.*
