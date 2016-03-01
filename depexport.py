import json

class DEPExporterI:
    def export(self, receipts):
        raise NotImplementedError("Please implement this yourself.")

# Supports just one cert and no cert chain for now.
class DEPExporter(DEPExporterI):
    def __init__(self, certFile):
        self.cert = ''
        if certFile:
            with open(certFile) as f:
                lines = f.readlines()[1:-1]
                lines = [ l.strip() for l in lines ]
                self.cert = ''.join(lines)

    def export(self, receipts):
        data = { "Belege-Gruppe" :
                [
                    { "Signaturzertifikat" : self.cert,
                        "Zertifizierungsstellen" : [],
                        "Belege-kompakt" : receipts
                    }
                ]
               }
        return json.dumps(data, sort_keys=False, indent=2)
