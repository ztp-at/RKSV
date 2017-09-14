#!/usr/bin/env python2.7

###########################################################################
# Copyright 2017 ZT Prentner IT GmbH
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
###########################################################################

from builtins import int
from builtins import range

import gettext
_ = gettext.translation('rktool', './lang', fallback=True).gettext

# FIXME: ugly hack to work with both pillow and PIL
def img_to_bytes(img):
    if 'tobytes' in dir(img):
        return img.tobytes()
    return img.tostring()

try:
    import zbar

    def read_qr_codes(image):
        image = image.convert('L')
        width, height = image.size

        raw = img_to_bytes(image)
        zimg = zbar.Image(width, height, 'Y800', raw)

        scanner = zbar.ImageScanner()
        scanner.scan(zimg)

        return [ sym.data for sym in zimg if str(sym.type) == 'QRCODE' ]

except ImportError:
    from jnius import autoclass

    ZImage = autoclass('net.sourceforge.zbar.Image')
    ZImageScanner = autoclass('net.sourceforge.zbar.ImageScanner')
    ZSymbol = autoclass('net.sourceforge.zbar.Symbol')

    def read_qr_codes(image):
        image = image.convert('L')
        width, height = image.size

        raw = img_to_bytes(image)
        zimg = ZImage(width, height, 'Y800')
        zimg.setData(raw)

        scanner = ZImageScanner()
        if scanner.scanImage(zimg) == 0:
            return list()

        syms = list()
        it = zimg.getSymbols().iterator()
        while it.hasNext():
            sym = it.next()
            if sym.getType() == ZSymbol.QRCODE:
                syms.append(sym.getData())

        return syms

if __name__ == "__main__":
    import gettext
    gettext.install('rktool', './lang', True)

    import sys
    from PIL import Image

    if len(sys.argv) < 2:
        print("Usage: ./img_decode.py <image file>...")
        sys.exit(0)

    for fn in sys.argv[1:]:
        with Image.open(fn) as img:
            for qr in read_qr_codes(img):
                print(qr)
