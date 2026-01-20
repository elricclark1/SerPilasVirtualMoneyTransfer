[app]
title = VirtualMoney
package.name = virtualmoney
package.domain = org.test
source.dir = .
source.include_exts = py
version = 1.1
requirements = python3,kivy,flask==2.3.3,flask-sqlalchemy,sqlalchemy,qrcode,pillow,pyjnius,greenlet>=3.0.2,typing-extensions,jinja2==3.1.2,werkzeug==2.2.3,itsdangerous==2.1.2,click==8.1.7,markupsafe==2.1.3,blinker==1.6.2,android
orientation = portrait
fullscreen = 0
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE
android.api = 33
android.minapi = 21
android.ndk = 25b
android.accept_sdk_license = True
android.archs = arm64-v8a
p4a.branch = master

[buildozer]
log_level = 2
warn_on_root = 1
