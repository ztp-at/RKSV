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
        :param receipts: A list receipt objects.
        :return: The JSON for the DEP as a string.
        """
        raise NotImplementedError("Please implement this yourself.")

# Supports just one cert and no cert chain for now.
class DEPExporter(DEPExporterI):
    """
    A primitive DEP exporter. It generates one group of receipts with a fixed or
    no certificate.
    """

    def __init__(self, prefix, certFile):
        """
        Creates a DEPExporter.
        :param prefix: The ID of the algorithm used.
        :param certFile: The path to a file containing a certificate in PEM
        format or None if no certificate should be used.
        """
        self.prefix = prefix
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
                        "Belege-kompakt" : [r.toJWSString(self.prefix)
                            for r in receipts]
                    }
                ]
               }
        return json.dumps(data, sort_keys=False, indent=2)

# Supports no certs and no groups
class CSVExporter(DEPExporterI):
    """
    Exports a DEP to CSV format.
    """

    def __init__(self, prefix):
        """
        Creates a CSVExporter.
        :param prefix: The ID of the algorithm used.
        """
        self.prefix = prefix

    def export(self, receipts):
        ret = 'Alg+ZDA;Register ID;Receipt ID;Date+Time;Sum A;Sum B;Sum C;Sum D;Sum E;Turnover Counter;Cert. Serial;Chaining Value;Signature'
        for r in receipts:
            ret = ret + '\n' + r.toCSV(self.prefix)
        return ret
