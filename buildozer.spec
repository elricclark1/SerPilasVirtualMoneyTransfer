[app]
title = HelloTest
package.name = hellotest
package.domain = org.test
source.dir = .
source.include_exts = py
version = 0.1
requirements = python3,kivy==2.3.0,flask,flask-sqlalchemy,sqlalchemy,qrcode,pillow,greenlet,typing-extensions,jinja2,werkzeug,itsdangerous,click,markupsafe
orientation = portrait
fullscreen = 0
android.permissions = INTERNET
android.api = 33
android.minapi = 21
android.ndk = 25b
android.accept_sdk_license = True
android.archs = arm64-v8a
p4a.branch = master

[buildozer]
log_level = 2
warn_on_root = 1
