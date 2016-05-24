#!/usr/bin/python2

from builtins import int

import zbar

from PIL import Image

def read_qr_codes(image):
    image = image.convert('L')
    width, height = image.size

    raw = image.tobytes()
    zimg = zbar.Image(width, height, 'Y800', raw)

    scanner = zbar.ImageScanner()
    scanner.scan(zimg)

    return [ sym.data for sym in zimg if str(sym.type) == 'QRCODE' ]

import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./img_decode.py <image file>...")
        sys.exit(0)

    for fn in sys.argv[1:]:
        with Image.open(fn) as img:
            for qr in read_qr_codes(img):
                print(qr)
