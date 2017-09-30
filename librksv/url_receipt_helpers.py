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

import re
import requests

from . import verify_receipt

def getBasicCodeFromURL(url):
    """
    Downloads the basic code representation of a receipt from
    the given URL.
    :param url: The URL as a string.
    :return: The basic code representation as a string.
    """
    r = requests.get(url)
    r.raise_for_status()
    return r.json()['code']

urlHashRegex = re.compile(
        r'(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{11}(?![A-Za-z0-9_-])')
def getURLHashFromURL(url):
    """
    Extracts the URL hash from the given URL. If an anchor part is given,
    it is used as the hash.
    :param url: The URL to search for the hash.
    :return: The hash as a base64 URL encoded string without padding or
    None if the hash could not be found.
    """
    urlParts = url.split('#')
    if len(urlParts) >= 2:
        return urlParts[1]

    matches = urlHashRegex.findall(urlParts[0])
    if len(matches) == 0:
        return None

    return matches[-1]

def getAndVerifyReceiptURL(rv, url):
    basicCode = getBasicCodeFromURL(url)
    urlHash = getURLHashFromURL(url)
    rec, algorithm = rv.verifyBasicCode(basicCode)
    verify_receipt.verifyURLHash(rec, algorithm, urlHash)
