"""Generate assets/icon.ico (and icon.png) — a radar/scan motif."""

import math
import os

from PIL import Image, ImageDraw

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.join(REPO, "assets")
os.makedirs(ASSETS, exist_ok=True)

S = 512
A = (108, 140, 255)   # blue
B = (167, 139, 250)   # violet


def lerp(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


def rounded_mask(size, radius):
    m = Image.new("L", (size, size), 0)
    ImageDraw.Draw(m).rounded_rectangle((0, 0, size - 1, size - 1), radius=radius, fill=255)
    return m


def render():
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    grad = Image.new("RGBA", (S, S))
    px = grad.load()
    for y in range(S):
        for x in range(S):
            t = (x + y) / (2 * S)
            r, g, b = lerp(A, B, t)
            px[x, y] = (r, g, b, 255)
    img.paste(grad, (0, 0), rounded_mask(S, int(S * 0.22)))

    d = ImageDraw.Draw(img, "RGBA")
    cx = cy = S / 2
    white = (255, 255, 255, 230)
    # radar rings
    for rr in (0.34, 0.24, 0.14):
        r = S * rr
        d.ellipse((cx - r, cy - r, cx + r, cy + r), outline=white, width=5)
    # cross hairs
    d.line((cx - S * 0.34, cy, cx + S * 0.34, cy), fill=(255, 255, 255, 150), width=3)
    d.line((cx, cy - S * 0.34, cx, cy + S * 0.34), fill=(255, 255, 255, 150), width=3)
    # sweep wedge
    sweep = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    sd = ImageDraw.Draw(sweep)
    r = S * 0.34
    sd.pieslice((cx - r, cy - r, cx + r, cy + r), -60, -10, fill=(255, 255, 255, 90))
    img.alpha_composite(sweep)
    ang = math.radians(-35)
    d.line((cx, cy, cx + math.cos(ang) * r, cy + math.sin(ang) * r), fill=(255, 255, 255, 255), width=6)
    # blip
    d.ellipse((cx + 70, cy - 90, cx + 90, cy - 70), fill=(47, 211, 154, 255))
    d.ellipse((cx - 8, cy - 8, cx + 8, cy + 8), fill=(255, 255, 255, 255))
    return img


def main():
    icon = render()
    icon.save(os.path.join(ASSETS, "icon.png"))
    icon.save(os.path.join(ASSETS, "icon.ico"), format="ICO",
              sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print("wrote", os.path.join(ASSETS, "icon.ico"))


if __name__ == "__main__":
    main()
