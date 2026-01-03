import os
import socket
import qrcode
import io
import threading
import time
import webbrowser

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.image import Image
from kivy.uix.button import Button
from kivy.clock import Clock
from kivy.core.image import Image as CoreImage
from kivy.utils import platform
from kivy.logger import Logger

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # doesn't even have to be reachable
        s.connect(('8.8.8.8', 1))
        IP = s.getsockname()[0]
        s.close()
    except Exception:
        IP = '127.0.0.1'
    return IP

class HostController(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = 30
        self.spacing = 20
        self.background_color = (0.1, 0.1, 0.1, 1) # Dark bg

        # Title
        self.add_widget(Label(
            text='Serpilas Virtual Money\nServer Console',
            font_size='28sp',
            size_hint_y=0.15,
            bold=True,
            halign='center'
        ))

        # Status Label
        self.status_label = Label(
            text='Initializing...', 
            font_size='18sp',
            size_hint_y=0.1,
            color=(0.8, 0.8, 0.8, 1)
        )
        self.add_widget(self.status_label)

        # IP Label
        self.ip_label = Label(
            text='IP: Finding...', 
            font_size='22sp',
            size_hint_y=0.15,
            color=(1, 1, 0, 1), # Yellow
            halign='center'
        )
        self.add_widget(self.ip_label)

        # QR Code Image
        self.qr_image = Image(size_hint_y=0.4, allow_stretch=True)
        self.add_widget(self.qr_image)

        # Admin Button
        self.admin_btn = Button(
            text='OPEN ADMIN PANEL',
            size_hint_y=0.15,
            background_color=(0.2, 0.6, 1, 1),
            font_size='20sp',
            bold=True
        )
        self.admin_btn.bind(on_press=self.open_admin)
        self.add_widget(self.admin_btn)
        
        # Start Service logic
        self.start_service()
        
        # Update UI with IP and QR
        self.update_info()
        
        # Schedule IP update every 5 seconds to handle network changes
        Clock.schedule_interval(self.update_info, 5.0)

    def start_service(self):
        if platform == 'android':
            from jnius import autoclass
            service_name = 'org.wiremoney.monopoly.ServiceFlask_service'
            service = autoclass(service_name)
            mActivity = autoclass('org.kivy.android.PythonActivity').mActivity
            argument = ''
            service.start(mActivity, argument)
            self.status_label.text = 'Background Service Running'
            Logger.info('WireMoney: Service started via jnius')
        else:
            self.status_label.text = 'Service: Manual (Not Android)'
            Logger.info('WireMoney: Not on Android, skipping service start')

    def open_admin(self, instance):
        # Open localhost in system browser
        webbrowser.open('http://127.0.0.1:5000/host_login')

    def update_info(self, dt=None):
        ip = get_local_ip()
        url = f"http://{ip}:5000"
        
        if ip == '127.0.0.1' or ip.startswith('10.0.2'): # 10.0.2.x is often the emulator NAT
             self.ip_label.text = f"Status: OFFLINE\nIP: {ip}\n\n⚠️ CONNECT TO WI-FI ⚠️"
             self.ip_label.color = (1, 0, 0, 1) # Red
        else:
             self.ip_label.text = f"Server Online at:\n{url}"
             self.ip_label.color = (0, 1, 0, 1) # Green
        
        # Generate QR
        qr = qrcode.QRCode(version=1, box_size=10, border=2)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to Kivy Texture
        data = io.BytesIO()
        img.save(data, format='png')
        data.seek(0)
        im = CoreImage(data, ext='png')
        self.qr_image.texture = im.texture

class MainApp(App):
    def build(self):
        return HostController()

if __name__ == '__main__':
    MainApp().run()
