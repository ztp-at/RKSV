class RKSVVerificationProxyI(object):
    def verify(self, fd, keyStore, aesKey, inState, registerIdx, chunksize):
        raise NotImplementedError("Please implement this yourself.")

from sys import version_info
if version_info[0] < 3:
    import __builtin__
else:
    import builtins as __builtin__

from librksv import depparser
from librksv import key_store
from librksv import receipt
from librksv import verification_state
from librksv import verify
from librksv import verify_receipt

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
