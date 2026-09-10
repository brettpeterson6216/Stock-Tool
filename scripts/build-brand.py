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
from PIL import Image, ImageDraw, ImageFont

SRC, OUT, MODE = sys.argv[1], sys.argv[2], sys.argv[3]
CHECK = MODE == "--check"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GROUND = (16, 15, 14)   # #100f0e - the same --rp-bg the site paints

def load():
    im = Image.open(SRC).convert("RGBA")
    s = min(im.size)
    l, t = (im.width - s) // 2, (im.height - s) // 2
    return im.crop((l, t, l + s, t + s))

def mark(size):
    return load().resize((size, size), Image.LANCZOS)

def tile(size, pad=0.0):
    canvas = Image.new("RGB", (size, size), GROUND)
    inner = round(size * (1 - 2 * pad))
    art = load().resize((inner, inner), Image.LANCZOS)
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
b64 = base64.b64encode(png_bytes(mark(192))).decode()
svg = (
    '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
    'viewBox="0 0 192 192" width="192" height="192" role="img" aria-label="Implied Lens">'
    "<title>Implied Lens</title>"
    f'<image width="192" height="192" xlink:href="data:image/png;base64,{b64}"/>'
    "</svg>"
)
written.append(emit("logo.svg", svg.encode()))

# Open Graph / Twitter card. Every shared link used to render with a stale
# product screenshot; this is the mark, the wordmark and one line, on the
# brand ground, in the brand face.
def brand_font(name, size):
    p = os.path.join(ROOT, "brand", "fonts", name)
    if os.path.exists(p):
        return ImageFont.truetype(p, size)
    return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", size)

card = Image.new("RGB", (1200, 630), GROUND)
d = ImageDraw.Draw(card)
for i in range(250, 0, -3):                    # the warm field the heroes use
    t = i / 250.0
    d.ellipse([215 - i, 315 - i, 215 + i, 315 + i],
              fill=(int(GROUND[0] + 24 * (1 - t) ** 2),
                    int(GROUND[1] + 18 * (1 - t) ** 2),
                    int(GROUND[2] + 7 * (1 - t) ** 2)))
art = mark(320)
card.paste(art, (55, 155), art)
bold = brand_font("PlusJakartaSans-Bold.ttf", 76)
reg = brand_font("PlusJakartaSans-Regular.ttf", 30)
small = brand_font("PlusJakartaSans-Bold.ttf", 22)
d.text((430, 214), "Implied", font=bold, fill=(242, 239, 230))
d.text((430 + d.textlength("Implied", font=bold), 214), " Lens", font=bold, fill=(232, 167, 51))
d.text((434, 320), "Research the business. Test the thesis.", font=reg, fill=(198, 193, 181))
d.text((434, 360), "Revisit the decision.", font=reg, fill=(198, 193, 181))
d.text((434, 430), "I M P L I E D L E N S . C O M", font=small, fill=(157, 152, 140))
written.append(emit("social-card.png", png_bytes(card)))

for name, n in written:
    print(f"  {name:28} {n/1024:7.1f} KB")
print(("Verified " if CHECK else "Built ") + f"{len(written)} brand assets from brand/logo-source.png")
