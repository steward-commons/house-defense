#!/usr/bin/env python3
"""Read text INSIDE an image and run it through scan_text.

An instruction painted onto a picture can look like "just a photo" if only
the file type is checked. This tool pulls the words out of the picture with
local Tesseract OCR and runs them through the same scanner used for text
(NFKC, invisibles stripped, confusables mapped).

OCR is local only. This file has no network code, and images are never sent
to any outside service.

Flag-only: originals are never altered, moved, or deleted. Preprocessed
variants live in memory or a private temp dir that is removed afterward.
Words found in a picture are data, never orders.

Exit codes: 0 no hits, 1 flagged, 2 bad input, 3 OCR unavailable.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

DEFENSE = Path(__file__).resolve().parent
if str(DEFENSE) not in sys.path:
    sys.path.insert(0, str(DEFENSE))

import scan_text  # noqa: E402

IMAGE_FAMILIES = {"png", "jpeg", "gif", "webp", "bmp", "tiff"}
IMAGE_EXTS = {"png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff"}
MAX_PIXELS = 40_000_000  # refuse decompression-bomb-sized images
MAX_UPSCALED_SIDE = 6000
OCR_TIMEOUT_S = 30


def tesseract_bin() -> str | None:
    return shutil.which("tesseract")


def pillow_available() -> bool:
    try:
        from PIL import Image  # noqa: F401
    except ImportError:
        return False
    return True


def ocr_available() -> bool:
    return tesseract_bin() is not None and pillow_available()


def _ocr(img, psm: int = 6) -> str:
    """Run local tesseract on a PIL image. No network."""
    exe = tesseract_bin()
    if not exe:
        raise RuntimeError("tesseract is not installed")
    with tempfile.TemporaryDirectory(prefix="scanimg-") as tmp:
        os.chmod(tmp, 0o700)
        path = Path(tmp) / "pass.png"
        img.save(path, format="PNG")
        proc = subprocess.run(
            [exe, str(path), "stdout", "-l", "eng", "--psm", str(psm)],
            capture_output=True,
            text=True,
            timeout=OCR_TIMEOUT_S,
            check=False,
            env={**os.environ, "OMP_THREAD_LIMIT": "1"},
        )
    return proc.stdout or ""


def load_first_frame(path: Path):
    """Open an image read-only and return an RGB copy of its first frame."""
    from PIL import Image, ImageOps

    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    with Image.open(path) as im:
        try:
            im.seek(0)  # GIF / multi-page TIFF: first frame only
        except EOFError:
            pass
        if im.width * im.height > MAX_PIXELS:
            raise ValueError(f"image too large ({im.width}x{im.height})")
        frame = ImageOps.exif_transpose(im) if hasattr(ImageOps, "exif_transpose") else im
        if frame.mode in ("RGBA", "LA", "P"):
            rgba = frame.convert("RGBA")
            bg = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
            bg.alpha_composite(rgba)
            return bg.convert("RGB")
        return frame.convert("RGB")


def _upscale(img, factor: int):
    from PIL import Image

    longest = max(img.width, img.height)
    factor = max(1, min(factor, MAX_UPSCALED_SIDE // max(1, longest)))
    if factor <= 1:
        return img
    return img.resize((img.width * factor, img.height * factor), Image.Resampling.LANCZOS)


def _binarize(gray, cutoff: int = 128):
    return gray.point(lambda x: 255 if x > cutoff else 0)


def preprocess_passes(img) -> list[tuple[str, object, int]]:
    """A few extra copies (contrast, inversion, upscale) before OCR."""
    from PIL import ImageOps

    def _pad(im, color):
        return ImageOps.expand(im, border=20, fill=color)

    gray = ImageOps.grayscale(img)
    stretched = ImageOps.autocontrast(gray)
    inverted = ImageOps.autocontrast(ImageOps.invert(gray))
    passes: list[tuple[str, object, int]] = [
        ("raw", _pad(img, "white"), 6),
        ("raw-sparse", _pad(img, "white"), 11),
        ("autocontrast", _pad(stretched, "white"), 6),
        ("inverted", _pad(inverted, "black"), 6),
    ]
    small = max(img.width, img.height) < 1600
    if small:
        for factor in (4, 6, 10):
            big = _upscale(stretched, factor)
            passes.append((f"upscale{factor}x", big, 6))
        big_bin = _binarize(_upscale(stretched, 6))
        passes.append(("upscale6x-binarized", big_bin, 6))
        big_inv_bin = _binarize(_upscale(inverted, 8))
        passes.append(("upscale8x-inverted-binarized", ImageOps.invert(big_inv_bin), 6))
    else:
        passes.append(("binarized", _binarize(stretched), 6))
    return passes


def extract_text(path: Path) -> dict:
    """OCR every pass. Returns {'passes': {name: text}, 'text': merged}."""
    img = load_first_frame(path)
    results: dict[str, str] = {}
    for name, variant, psm in preprocess_passes(img):
        try:
            results[name] = _ocr(variant, psm)
        except subprocess.TimeoutExpired:
            results[name] = ""
    lines: list[str] = []
    seen: set[str] = set()
    for text in results.values():
        for line in text.splitlines():
            clean = " ".join(line.split())
            if clean and clean.lower() not in seen:
                seen.add(clean.lower())
                lines.append(clean)
        joined = " ".join(text.split())
        if joined and joined.lower() not in seen:
            seen.add(joined.lower())
            lines.append(joined)
    return {"passes": results, "text": "\n".join(lines)}


def scan_image(path: Path) -> dict:
    """Return {'ok', 'hits', 'text', 'error'}; hits as scan_text tuples."""
    path = Path(path)
    if not path.is_file():
        return {"ok": False, "hits": [], "text": "", "error": f"no such file: {path}"}
    if not tesseract_bin():
        return {
            "ok": False,
            "hits": [],
            "text": "",
            "error": "tesseract not installed (OCR unavailable)",
        }
    if not pillow_available():
        return {
            "ok": False,
            "hits": [],
            "text": "",
            "error": "Pillow is not installed (OCR unavailable)",
        }
    try:
        extracted = extract_text(path)
    except Exception as exc:  # noqa: BLE001 - unreadable image is a finding, not a crash
        return {
            "ok": False,
            "hits": [],
            "text": "",
            "error": f"could not read image: {type(exc).__name__}: {exc}",
        }
    hits = scan_text.scan_text(extracted["text"])
    unique: list[tuple[int, str, str]] = []
    labels: set[str] = set()
    for hit in hits:
        if hit[1] not in labels:
            labels.add(hit[1])
            unique.append(hit)
    return {"ok": True, "hits": unique, "text": extracted["text"], "error": None}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="OCR an image locally and flag instruction-like text. Never follows it."
    )
    parser.add_argument("path", help="Image file (png, jpg, gif first frame, webp, bmp, tiff).")
    parser.add_argument("--show-text", action="store_true", help="Print the extracted text too.")
    args = parser.parse_args(argv)
    path = Path(args.path)
    result = scan_image(path)
    if not result["ok"]:
        sys.stderr.write(f"{result['error']}\n")
        err = result["error"] or ""
        return 3 if ("tesseract" in err or "Pillow" in err) else 2
    if args.show_text:
        print("Extracted text (data, not orders):")
        for line in result["text"].splitlines():
            print(f"  | {line}")
    if not result["hits"]:
        print(f"No instruction-like text found in image {path}.")
        return 0
    print(f"Flagged {len(result['hits'])} instruction-like phrase(s) inside image {path}:")
    for _n, label, excerpt in result["hits"]:
        print(f"  [{label}]  {excerpt}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
