import base64
import jwt.algorithms

class SignaturerstellungseinheitI:
    def sign(self, data):
        raise NotImplementedError("Please implement this yourself.")

    def serial(self):
        raise NotImplementedError("Please implement this yourself.")

class SignaturerstellungseinheitBroken(SignaturerstellungseinheitI):
    def __init__(self, serial):
        self.serial = serial

    def sign(self, data):
        alg = '{"alg":"ES256"}'.encode("utf-8")
        sig = 'Sicherheitseinrichtung ausgefallen'.encode("utf-8")

        alg = base64.urlsafe_b64encode(alg).replace(b'=', b'')
        data = base64.urlsafe_b64encode(data).replace(b'=', b'')
        sig = base64.urlsafe_b64encode(sig).replace(b'=', b'')

        return alg + b'.' + data + b'.' + sig

    def serial(self):
        return serial

class SignaturerstellungseinheitWorking(SignaturerstellungseinheitI):
    def __init__(self, serial, privKeyFile):
        self.serial = serial

        with open(privKeyFile) as f:
            self.secret = f.read()

    def sign(self, data):
        algo = jwt.algorithms.get_default_algorithms()['ES256']

        alg = '{"alg":"ES256"}'.encode("utf-8")
        alg = base64.urlsafe_b64encode(alg).replace(b'=', b'')

        data = base64.urlsafe_b64encode(data).replace(b'=', b'')

        key = algo.prepare_key(self.secret)
        sig = algo.sign(alg + b'.' + data, key)

        sig = base64.urlsafe_b64encode(sig).replace(b'=', b'')

        return alg + b'.' + data + b'.' + sig

    def serial(self):
        return serial
