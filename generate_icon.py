"""Generates assets/icon.ico from the same leaf glyph used for the tray icon.

Run before pyinstaller so the built exe (and its taskbar/file-explorer icon) match the
app's own green leaf instead of PyInstaller's default icon:
    python generate_icon.py
"""

from pathlib import Path

from eco_enforcer import create_tray_icon_image

ICON_PATH = Path(__file__).parent / "assets" / "icon.ico"

# Windows .ico files bundle multiple resolutions; Pillow generates each straight from a
# high-res source image rather than upscaling a small one, so render at the largest size.
_ICO_SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]


def main() -> None:
    ICON_PATH.parent.mkdir(parents=True, exist_ok=True)
    image = create_tray_icon_image("#22C55E", size=256)
    image.save(ICON_PATH, sizes=_ICO_SIZES)
    print(f"Wrote {ICON_PATH}")


if __name__ == "__main__":
    main()
