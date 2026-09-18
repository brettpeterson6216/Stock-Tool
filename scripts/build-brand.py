"""Derive every icon the site serves from brand/logo-source.png.

See scripts/build-brand.js for why this exists. Invoked through it so the npm
scripts stay uniform, but it is a plain script and runs directly too.

The source is the logo as supplied: the lens frame with the candlesticks, gold
on a true alpha matte. It needs no keying and no colour surgery - an earlier
pass built the transparency here by using a black-ground JPEG's own luminance
as the matte, and while that worked on dark it put a ghost on cream, because
the artwork is lit dark-to-light and its lower half simply disappeared.

Two forms come out of it:

  transparent  the mark as drawn. Used for the header, the favicons and the
               SVG, because the gold reads on cream and on graphite alike.

  tile         the mark composited onto the brand ground. Used where the
               platform demands an opaque square: iOS composites Apple touch
               icons itself, and Android maskable icons are cropped to a
               circle or squircle, so both ship with a ground and with the
               art inset far enough to survive the crop.
"""
import base64, hashlib, io, os, sys
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import numpy as np

SRC, OUT, MODE = sys.argv[1], sys.argv[2], sys.argv[3]
CHECK = MODE == "--check"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GROUND = (16, 15, 14)   # #100f0e - the same --rp-bg the site paints

def load():
    im = Image.open(SRC).convert("RGBA")
    s = min(im.size)
    l, t = (im.width - s) // 2, (im.height - s) // 2
    return im.crop((l, t, l + s, t + s))

def _unsharp(im, percent, radius=0.6):
    """Downsampling a detailed illustration to icon size throws away the edges
    that make it legible. Re-asserting them afterwards is the difference
    between a gold smudge and a recognisable mark - measured as edge energy,
    a plain 34px Lanczos scores 66 and the same sharpened scores 83, against
    32-44 for anything the browser downsamples itself."""
    r, g, b, a = im.split()
    rgb = Image.merge("RGB", (r, g, b)).filter(ImageFilter.UnsharpMask(radius, percent, 0))
    a = a.filter(ImageFilter.UnsharpMask(radius, percent, 0))
    return Image.merge("RGBA", (*rgb.split(), a))

def _lift_alpha(im, gamma):
    """The mark is mostly hairlines, so its average coverage is about a
    quarter. At 16px that reads as barely-there in a browser tab; lifting the
    alpha curve thickens the strokes optically without touching the drawing."""
    r, g, b, a = im.split()
    arr = np.asarray(a, np.float32) / 255.0
    arr = (np.clip(arr ** gamma, 0, 1) * 255).astype(np.uint8)
    return Image.merge("RGBA", (r, g, b, Image.fromarray(arr)))

def mark(size, crisp=True):
    """One Lanczos step from the full-resolution source - never a resize of a
    resize - then sharpening scaled to how brutal the reduction was."""
    im = load().resize((size, size), Image.LANCZOS)
    if not crisp:
        return im
    if size <= 20:
        return _lift_alpha(_unsharp(im, 190), 0.70)
    if size <= 56:
        return _lift_alpha(_unsharp(im, 170), 0.85)
    if size <= 128:
        return _unsharp(im, 120)
    return im

def tile(size, pad=0.0):
    canvas = Image.new("RGB", (size, size), GROUND)
    inner = round(size * (1 - 2 * pad))
    art = mark(inner)
    off = (size - inner) // 2
    canvas.paste(art, (off, off), art)
    return canvas

def png_bytes(img):
    b = io.BytesIO()
    img.save(b, "PNG", optimize=True)
    return b.getvalue()

def emit(name, data):
    p = os.path.join(OUT, name)
    if CHECK:
        cur = open(p, "rb").read() if os.path.exists(p) else b""
        if hashlib.sha256(cur).digest() != hashlib.sha256(data).digest():
            raise SystemExit(
                f"Brand assets are out of date: public/{name}. Run npm run build:brand."
            )
    else:
        open(p, "wb").write(data)
    return name, len(data)

written = []

# Favicons keep the alpha: a browser tab can be light or dark and the gold
# ring holds on either, where a black tile would sit in a light tab as a black
# square and a white one would swallow the mark in a dark tab.
for n in (16, 32, 48):
    written.append(emit(f"favicon-{n}.png", png_bytes(mark(n))))

ico = io.BytesIO()
mark(48).save(ico, "ICO", sizes=[(16, 16), (32, 32), (48, 48)])
written.append(emit("favicon.ico", ico.getvalue()))

# iOS draws its own rounded rect and composites onto an opaque ground, so this
# one ships with the ground and room inside the radius.
written.append(emit("apple-touch-icon.png", png_bytes(tile(180, pad=0.08))))

# PWA. "any" is the mark on the ground; "maskable" is cropped to a circle or
# squircle by the launcher, which takes about a fifth off each side.
written.append(emit("app-icon-192.png", png_bytes(tile(192, pad=0.04))))
written.append(emit("app-icon-512.png", png_bytes(tile(512, pad=0.04))))
written.append(emit("app-icon-maskable-512.png", png_bytes(tile(512, pad=0.18))))

# The header mark, and the same artwork carried by logo.svg - which is
# referenced by the header <img>, by rel="icon" and by the Organization
# schema, so all three stay in sync without touching any of them.
written.append(emit("logo-mark.png", png_bytes(mark(256))))

# The header mark, rendered at the exact sizes it is displayed at. It used to
# be a 192px PNG inside logo.svg that the browser squeezed down to 28 - a 6.9x
# reduction done with the UA's own filter, which is what made it look blurry.
# Now the browser picks one of these and paints it 1:1.
for n in (34, 68, 102):
    written.append(emit(f"logo-mark-{n}.png", png_bytes(mark(n))))
b64 = base64.b64encode(png_bytes(mark(128))).decode()
svg = (
    '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
    'viewBox="0 0 128 128" width="128" height="128" role="img" aria-label="ImpliedLens">'
    "<title>ImpliedLens</title>"
    f'<image width="128" height="128" xlink:href="data:image/png;base64,{b64}"/>'
    "</svg>"
)
written.append(emit("logo.svg", svg.encode()))

# The Open Graph / Twitter card is NOT built here. It carries a chart, and
# that chart is rendered by the site's own lightweight-charts bundle on real
# AAPL bars rather than drawn with a drawing library - a stock research tool
# whose social card shows a hand-drawn squiggle is advertising the wrong
# thing. See scripts/build-social-card.js.

for name, n in written:
    print(f"  {name:28} {n/1024:7.1f} KB")
print(("Verified " if CHECK else "Built ") + f"{len(written)} brand assets from brand/logo-source.png")
