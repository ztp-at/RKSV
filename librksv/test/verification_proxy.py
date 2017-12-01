###########################################################################
# Copyright 2017 ZT Prentner IT GmbH (www.ztp.at)
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

from ..gettext_helper import _

class RKSVVerificationProxyI(object):
    def verify(self, fd, keyStore, aesKey, inState, registerIdx, chunksize):
        raise NotImplementedError("Please implement this yourself.")

from sys import version_info
if version_info[0] < 3:
    import __builtin__
else:
    import builtins as __builtin__

from .. import depparser
from .. import key_store
from .. import receipt
from .. import verification_state
from .. import verify
from .. import verify_receipt

class LibRKSVVerificationProxy(RKSVVerificationProxyI):
    def __init__(self, pool, nprocs):
        self.pool = pool
        self.nprocs = nprocs

    def verify(self, fd, keyStore, aesKey, inState, registerIdx, chunksize):
        # Save the _() function.
        trvec = (
            __builtin__._ ,
            depparser._,
            key_store._,
            receipt._,
            verification_state._,
            verify._,
            verify_receipt._,
        )
        # Temporarily disable translations to make sure error
        # messages match.
        (
            __builtin__._ ,
            depparser._,
            key_store._,
            receipt._,
            verification_state._,
            verify._,
            verify_receipt._,
        ) = [lambda x: x] * len(trvec)

        try:
            parser = depparser.IncrementalDEPParser.fromFd(fd, True)
            outState = verify.verifyParsedDEP(parser, keyStore, aesKey, inState,
                    registerIdx, self.pool, self.nprocs, chunksize)
        finally:
            (
                __builtin__._ ,
                depparser._,
                key_store._,
                receipt._,
                verification_state._,
                verify._,
                verify_receipt._,
            ) = trvec

        return outState
