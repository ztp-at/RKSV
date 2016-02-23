import base64

class SignaturerstellungseinheitI:
    def sign(self, data, algorithm):
        raise NotImplementedError("Please implement this yourself.")

    def serial(self):
        raise NotImplementedError("Please implement this yourself.")

class SignaturerstellungseinheitBroken(SignaturerstellungseinheitI):
    def __init__(self, serial):
        self.serial = serial

    def sign(self, data, algorithm):
        head = algorithm.jwsHeader().encode("utf-8")
        sig = 'Sicherheitseinrichtung ausgefallen'.encode("utf-8")

        head = base64.urlsafe_b64encode(head).replace(b'=', b'')
        data = base64.urlsafe_b64encode(data).replace(b'=', b'')
        sig = base64.urlsafe_b64encode(sig).replace(b'=', b'')

        return head + b'.' + data + b'.' + sig

    def serial(self):
        return serial

class SignaturerstellungseinheitWorking(SignaturerstellungseinheitI):
    def __init__(self, serial, privKeyFile):
        self.serial = serial

        with open(privKeyFile) as f:
            self.secret = f.read()

    def sign(self, data, algorithm):
        head = algorithm.jwsHeader().encode("utf-8")
        head = base64.urlsafe_b64encode(head).replace(b'=', b'')

        sig = algorithm.sign(data, self.secret)

        data = base64.urlsafe_b64encode(data).replace(b'=', b'')

        return head + b'.' + data + b'.' + sig

    def serial(self):
        return serial
