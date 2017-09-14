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

"""
This module contains simple classes to export receipts in the DEP format.
"""
from builtins import int
from builtins import range

import gettext
_ = gettext.translation('rktool', './lang', fallback=True).gettext

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

    def addExtra(self, key, value):
        """
        Adds an extra item to the DEPs main dictionary.
        :param key: The key under that the extra data will be stored.
        :param value: The value of the extra data.
        """
        raise NotImplementedError("Please implement this yourself.")

class DEPExporter(DEPExporterI):
    """
    A primitive DEP exporter. It generates one group of receipts as a
    dictionary structure.
    """

    def __init__(self):
        self.groups = []
        self.extra = dict()

    def addGroup(self, receipt_tuples, cert=None, cert_chain=[]):
        self.groups.append((receipt_tuples, cert, cert_chain))

    def export(self):
        dep_groups = list()
        for g in self.groups:
            cert = utils.exportCertToPEM(g[1]) if g[1] else ""
            cert_chain = [utils.exportCertToPEM(c) for c in g[2]]
            dep_groups.append({
                "Signaturzertifikat": cert,
                "Zertifizierungsstellen": cert_chain,
                "Belege-kompakt": [r[0].toJWSString(r[1]) for r in
                    g[0]],
            })

        ret = { "Belege-Gruppe": dep_groups }
        ret.update(self.extra)
        return ret

    def addExtra(self, key, value):
        self.extra[key] = value

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

    def addExtra(self, key, value):
        pass
