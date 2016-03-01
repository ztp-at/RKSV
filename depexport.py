"""
This module contains simple classes to export receipts in the DEP format.
"""
import json

class DEPExporterI:
    """
    The base class for DEP exporters. It contains functions every exporter must
    implement. Do not use this directly.
    """

    def export(self, receipts):
        """
        Creates a DEP from the given list of receipts.
        :param receipts: A list of JWS formatted receipt strings.
        :return: The JSON for the DEP as a string.
        """
        raise NotImplementedError("Please implement this yourself.")

# Supports just one cert and no cert chain for now.
class DEPExporter(DEPExporterI):
    """
    A primitive DEP exporter. It generates one group of receipts with a fixed or
    no certificate.
    """

    def __init__(self, certFile):
        """
        Creates a DEPExporter.
        :param certFile: The path to a file containing a certificate in PEM
        format or None if no certificate should be used.
        """
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
