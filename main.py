import sys
import traceback
import threading
import socket
import io
import time

# Kivy Imports
from kivy.app import App
from kivy.clock import Clock, mainthread
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.image import Image
from kivy.uix.button import Button
from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition
from kivy.core.image import Image as CoreImage

# Flask Imports
# We assume app.py exists in the same directory and contains the Flask 'app' object
try:
    from app import app as flask_app, init_db, get_local_ip
except ImportError as e:
    flask_app = None
    init_error = traceback.format_exc()

# QR Code Imports
try:
    import qrcode
except ImportError:
    qrcode = None

class ErrorLabel(Label):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.text_size = (self.width, None)
        self.size_hint_y = None
        self.height = self.texture_size[1]
        self.halign = 'left'
        self.valign = 'top'
        self.bind(width=lambda *x: self.setter('text_size')(self, (self.width, None)))
        self.bind(texture_size=lambda *x: self.setter('height')(self, self.texture_size[1]))

class MenuScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=50, spacing=30)
        
        # Title
        title = Label(
            text="SerPilasVirtualMoney", 
            font_size='40sp', 
            color=(0.2, 0.8, 1, 1),
            bold=True,
            size_hint_y=0.4
        )
        layout.add_widget(title)
        
        # Start Button
        btn = Button(
            text="START NEW GAME",
            font_size='20sp',
            bold=True,
            size_hint_y=0.15,
            background_normal='',
            background_color=(0.2, 0.6, 0.2, 1), # Green
            color=(1, 1, 1, 1)
        )
        btn.bind(on_release=self.start_game)
        layout.add_widget(btn)
        
        # Spacer
        layout.add_widget(Label(size_hint_y=0.45))
        
        self.add_widget(layout)
    
    def start_game(self, instance):
        self.manager.transition = SlideTransition(direction='left')
        self.manager.current = 'server'

class ServerScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.server_started = False
        
        self.layout = BoxLayout(orientation='vertical', padding=50, spacing=20)
        
        # 1. URL Label
        self.url_label = Label(
            text="Initializing...", 
            font_size='24sp', 
            size_hint_y=0.1,
            color=(0.4, 1, 0.4, 1) # Green
        )
        self.layout.add_widget(self.url_label)

        # 2. QR Code Image
        self.qr_image = Image(size_hint_y=0.6, allow_stretch=True)
        self.layout.add_widget(self.qr_image)

        # 3. Status/Log Label
        self.log_label = Label(
            text="Ready to start...",
            size_hint_y=0.3,
            font_size='14sp',
            color=(0.8, 0.8, 0.8, 1)
        )
        self.layout.add_widget(self.log_label)
        
        self.add_widget(self.layout)

    def on_enter(self):
        """Called when the screen is displayed."""
        if not self.server_started:
            self.server_started = True
            self.log("Starting services...")
            Clock.schedule_once(self.start_server, 0.5)

    def get_ip(self):
        """Wi‑Fi LAN IP for URL/QR; on Android uses get_local_ip (WifiManager/NetworkInterface, no hostname -I)."""
        try:
            return get_local_ip()
        except NameError:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                return ip or "127.0.0.1"
            except Exception:
                return "127.0.0.1"

    def generate_qr(self, data):
        if not qrcode:
            self.log("Error: qrcode library not found")
            return
            
        try:
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(data)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert PIL image to Kivy Texture
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format='PNG')
            img_byte_arr.seek(0)
            
            im = CoreImage(img_byte_arr, ext='png')
            self.qr_image.texture = im.texture
        except Exception as e:
            self.log(f"QR Error: {e}")

    def log(self, msg):
        @mainthread
        def _update(text):
            self.log_label.text += f"\n{text}"
        _update(msg)

    def start_server(self, dt):
        try:
            # 1. Get IP
            ip = self.get_ip()
            self.log(f"DEBUG: main.py got IP: {ip}")
            port = 8080
            url = f"http://{ip}:{port}"
            
            # 2. Update UI
            self.url_label.text = url
            self.generate_qr(url)
            
            # 3. Start Flask Thread
            if flask_app:
                # Initialize DB if needed
                try:
                    init_db()
                    self.log("Database initialized.")
                except Exception as e:
                    self.log(f"DB Init Error: {e}")

                t = threading.Thread(target=self.run_flask, args=(ip, port))
                t.daemon = True
                t.start()
                self.log(f"Server running on {url}")
            else:
                self.log("CRITICAL: Flask app not found!")
                if 'init_error' in globals():
                    self.log(init_error)

        except Exception as e:
            self.log(f"Startup Error: {traceback.format_exc()}")

    def run_flask(self, ip, port):
        try:
            # Disable reloader to prevent main thread issues
            flask_app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
        except Exception as e:
            self.log(f"Flask Crashed: {e}")

class MainApp(App):
    def build(self):
        # Global Exception Catcher for the Kivy Loop
        sys.excepthook = self.handle_exception
        
        try:
            sm = ScreenManager()
            sm.add_widget(MenuScreen(name='menu'))
            sm.add_widget(ServerScreen(name='server'))
            return sm
        except Exception:
            return Label(text=traceback.format_exc(), color=(1, 0, 0, 1))

    def handle_exception(self, exc_type, exc_value, exc_traceback):
        """
        Catches crashes that happen AFTER build() returns (runtime crashes).
        Updates the root widget to show the error.
        """
        error_msg = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        
        # Safely update UI from whatever thread crashed
        @mainthread
        def show_error():
            # Replace current root with error label
            if self.root:
                self.root.clear_widgets()
                self.root.add_widget(Label(
                    text=f"CRASH DETECTED:\n\n{error_msg}", 
                    color=(1, 0, 0, 1),
                    font_size='16sp',
                    halign='left',
                    text_size=(self.root.width - 20, None)
                ))
        
        show_error()

if __name__ == '__main__':
    try:
        MainApp().run()
    except Exception:
        # Fallback for crashes before Kivy even starts
        print(traceback.format_exc())
