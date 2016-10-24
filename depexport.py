"""
This module contains simple classes to export receipts in the DEP format.
"""
from builtins import int

import json

import utils

class DEPExporterI(object):
    """
    The base class for DEP exporters. It contains functions every exporter
    must implement. Do not use this directly.
    """

    def addGroup(self, receipt_tuples, cert=None, cert_chain=[]):
        """
        Adds a new group to the DEP exporter.
        :param receipt_tuples: A list of tuples containing the algorithm ID
        for a receipt in the second and the actual receipt object in the
        first element.
        :param cert: The certificate object used for the group, or None if
        no certificate is supposed to show up in the DEP.
        :param cert_chain: A list of certificate objects containing the
        chain of signing certificates used for the group.
        """
        raise NotImplementedError("Please implement this yourself.")

    def export(self):
        """
        Creates a DEP containing the previously added groups.
        :return: The DEP as an exporter specific type.
        """
        raise NotImplementedError("Please implement this yourself.")

class DEPExporter(DEPExporterI):
    """
    A primitive DEP exporter. It generates one group of receipts as a
    dictionary structure.
    """

    def __init__(self):
        self.groups = []

    def addGroup(self, receipt_tuples, cert=None, cert_chain=[]):
        self.groups.append({
            'receipts': receipt_tuples,
            'cert': cert,
            'cert_chain': cert_chain,
        })

    def export(self):
        dep_groups = list()
        for g in self.groups:
            cert = utils.exportCertToPEM(g['cert']) if g['cert'] else ""
            cert_chain = [utils.exportCertToPEM(c) for c in
                    g['cert_chain']]
            dep_groups.append({
                "Signaturzertifikat": cert,
                "Zertifizierungsstellen": cert_chain,
                "Belege-kompakt": [r[0].toJWSString(r[1]) for r in
                    g['receipts']],
            })
        return { "Belege-Gruppe": dep_groups }

class JSONExporter(DEPExporter):
    """
    Exports a DEP to JSON format. It has the same limitations as
    DEPExporter.
    """

    def export(self):
        return json.dumps(super(JSONExporter, self).export(),
                sort_keys=False, indent=2)

# Supports no certs and no groups
class CSVExporter(DEPExporterI):
    """
    Exports a DEP to CSV format.
    """

    def __init__(self):
        self.receipts = []

    def addGroup(self, receipt_tuples, cert=None, cert_chain=[]):
        self.receipts.extend(receipt_tuples)

    def export(self):
        ret = 'Alg+ZDA;Register ID;Receipt ID;Date+Time;Sum A;Sum B;Sum C;Sum D;Sum E;Turnover Counter;Cert. Serial;Chaining Value;Signature'
        for r in self.receipts:
            ret = ret + '\n' + r[0].toCSV(r[1])
        return ret
