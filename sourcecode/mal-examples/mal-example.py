import base64
import os
import subprocess
import winreg
import socket

# Trigger "Check for base64-encoded strings"
encoded_string = b"SGVyZSBpcyBhIGxvbmcgYmFzZTY0IGVuY29kZWQgc3RyaW5nLg=="

# Trigger "Access to .ssh directory"
ssh_path = os.path.join(os.environ["HOME"], ".ssh")

# Trigger "Access to /etc/passwd"
with open("/etc/passwd", "r") as passwd_file:
    print(passwd_file.read())

# Trigger "Execution using subprocess"
subprocess.run(["echo", "Hello, world!"])

# Trigger "Use of socket module"
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Trigger "Access to environment variables"
user = os.getenv("USER")

# Trigger "Registry Key"
key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_WRITE)
winreg.SetValueEx(key, "MyApp", 0, winreg.REG_SZ, r"C:\Path\To\MyApp.exe")
winreg.CloseKey(key)
