"""Draw the tray icons: a small shield with a status dot.

States: ok (green), checking (amber), alert (red), paused (grey).
Run from the companion folder: python scripts/make_icons.py
"""

from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parents[1] / "assets"
NAVY = (27, 42, 74, 255)
STATES = {
    "ok": (46, 160, 67, 255),
    "checking": (219, 154, 4, 255),
    "alert": (218, 54, 51, 255),
    "paused": (139, 148, 158, 255),
}


def shield(size: int, dot: tuple[int, int, int, int]) -> Image.Image:
    scale = 4  # draw big, shrink for smooth edges
    s = size * scale
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    w = s * 0.78
    left = (s - w) / 2
    top = s * 0.08
    mid = s / 2
    d.polygon(
        [
            (mid, top),
            (left + w, top + s * 0.14),
            (left + w, top + s * 0.46),
            (mid, s * 0.94),
            (left, top + s * 0.46),
            (left, top + s * 0.14),
        ],
        fill=NAVY,
    )
    r = s * 0.2
    cx, cy = s * 0.72, s * 0.72
    d.ellipse([cx - r - s * 0.04, cy - r - s * 0.04, cx + r + s * 0.04, cy + r + s * 0.04], fill=(255, 255, 255, 255))
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=dot)
    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, color in STATES.items():
        shield(32, color).save(OUT / f"tray-{name}.png")
    shield(256, STATES["ok"]).save(OUT / "app.png")
    print(f"icons written to {OUT}")


if __name__ == "__main__":
    main()
