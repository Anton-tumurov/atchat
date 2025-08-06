import sys
import os
from cx_Freeze import setup, Executable

# Config Variables
APP_NAME = "@Chat"
VERSION = "0.1.0"
MAIN_SCRIPT = "atchat.py"
ICON_FILE = "icon.ico"
INSTALLER = "installer.iss"
ISCC = "C:\\Program Files (x86)\\Inno Setup 6\\ISCC.exe"

# cx_Freeze Setup
build_exe_options = {
    "packages": ["_cffi_backend"],
    "include_files": [
        ("assets", "assets")
    ],
    "optimize": 1
}

base = "Win32GUI" if sys.platform == "win32" else None

executables = [
    Executable(
        script=MAIN_SCRIPT,
        base=base,
        target_name=f"{APP_NAME}.exe",
        icon=f"assets/{ICON_FILE}"
    )
]

# Build App
setup(
    name=APP_NAME,
    version=VERSION,
    description=APP_NAME,
    options={"build_exe": build_exe_options},
    executables=executables
)

# Inno Setup Script
if os.path.exists(INSTALLER) and os.path.exists(ISCC):
    os.system(f"\"{ISCC}\" {INSTALLER}")
else:
    print(f"Installer \"{INSTALLER}\" or \"{ISCC}\" not found.")
