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

"""
This module contains simple classes to export receipts in the DEP format.
"""
from builtins import int
from builtins import range

from .gettext_helper import _

import itertools
import json

try:
    # ABCs live in "collections.abc" in Python >= 3.3
    from collections.abc import Generator
except ImportError:
    # fall back to import from "backports_abc"
    from backports_abc import Generator

from collections import OrderedDict

from . import utils

class DEPStream(Generator):
    """
    Takes a list (or generator) of tuples of the arguments described for the
    append() method and wraps them in a generator interface. Additionally, new
    lists (or generators) can be appended. This allows us to lazily merge such
    tuple lists.
    """

    @classmethod
    def fromIterList(cls, stream_list):
        return cls(itertools.chain(*stream_list))

    def __init__(self, stream=None):
        self._last = None
        if stream is None:
            self._backing = itertools.chain()
        else:
            self._backing = itertools.chain(stream)

    def send(self, dummy):
        return next(self._backing)

    def throw(self, type=None, value=None, traceback=None):
        raise StopIteration

    def append(self, receipt_tuples, cert=None, cert_chain=[]):
        """
        Adds a new group to the DEPStream.
        :param receipt_tuples: A list (or generator) of tuples containing the
        algorithm ID for a receipt in the second and the actual receipt object
        in the first element.
        :param cert: The certificate object used for the group, or None if
        no certificate is supposed to show up in the DEP.
        :param cert_chain: A list of certificate objects containing the
        chain of signing certificates used for the group.
        """
        ng = (receipt_tuples, cert, cert_chain)
        self._backing = itertools.chain(self._backing, [ng])

    def extend(self, more):
        self._backing = itertools.chain(self._backing, more)

class MergingDEPStream(DEPStream):
    """
    This implements the same interface as DEPStream with the exception, that
    the receipt lists in subsequent tuples will be merged if the certificate and
    certificate list match.
    """

    class _ReceiptTupleStream(Generator):
        def __init__(self, outer, rec_tuples, cert, cert_list):
            self._backing = itertools.chain(rec_tuples)
            self._outer = outer
            self.cert = cert
            self.cert_list = cert_list

        def send(self, value):
            while True:
                try:
                    return next(self._backing)
                except StopIteration:
                    # no more receipts, fetch next group, see if it continues
                    rec_tuples, cert, cert_list = next(self._outer._backing)
                    if self.cert == cert and cert_list == cert_list:
                        # more of this group, try again
                        self.extend(rec_tuples)
                        continue
                    # no additional receipts, reinsert extracted group and stop
                    self._outer._backing = itertools.chain(
                            [(rec_tuples, cert, cert_list)],
                            self._outer._backing)
                    raise

        def throw(self, type=None, value=None, traceback=None):
            raise StopIteration

        def extend(self, more):
            self._backing = itertools.chain(self._backing, more)

    def send(self, dummy):
        while True:
            rec_tuples, cert, cert_list = next(self._backing)

            if (self._last is None or self._last.cert != cert or
                    self._last.cert_list != cert_list):
                # new group
                self._last = MergingDEPStream._ReceiptTupleStream(self,
                        rec_tuples, cert, cert_list)
                return (self._last, cert, cert_list)

            # same group
            self._last.extend(rec_tuples)

class DEPExporterI(object):
    """
    The base class for DEP exporters. It contains functions every exporter
    must implement. Do not use this directly.
    """

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

    @classmethod
    def fromSingleGroup(cls, receipt_tuples, cert=None, cert_chain=[]):
        """
        Simplyfied interface to avoid having to use DEPStream manually when we
        only have one group.
        """
        generator = [(receipt_tuples, cert, cert_chain)]
        return cls(DEPStream(generator))

# from https://stackoverflow.com/questions/12670395/json-encoding-very-long-iterators
class FakeListIterator(list):
    def __init__(self, iterable):
        self.iterable = iter(iterable)
        try:
            self.firstitem = next(self.iterable)
            self.truthy = True
        except StopIteration:
            self.truthy = False

    def __iter__(self):
        if not self.truthy:
            return iter([])
        return itertools.chain([self.firstitem], self.iterable)

    def __len__(self):
        raise NotImplementedError("FakeListIterator has no length")

    def __getitem__(self, i):
        raise NotImplementedError("FakeListIterator has no getitem")

    def __setitem__(self, i, value):
        raise NotImplementedError("FakeListIterator has no setitem")

    def __nonzero__(self):
        return self.truthy

    def __bool__(self):
        return self.truthy

class DEPExporter(DEPExporterI):
    """
    Generates a dictionary structure. List elements are converted to generators.
    If this is not desired the constructor accepts an output_generator_wrapper,
    which can be used to create new lists from the generators (by passing list).
    """

    def __init__(self, dep_stream, output_generator_wrapper=id):
        self._stream = dep_stream
        self._wrapper = output_generator_wrapper
        self._extra = dict()

    def export(self):
        mkdict = lambda rs, c, cs: OrderedDict([
            ("Signaturzertifikat", utils.exportCertToPEM(c) if c else ""),
            ("Zertifizierungsstellen", [utils.exportCertToPEM(c) for c in cs]),
            ("Belege-kompakt", self._wrapper((r[0].toJWSString(r[1])
                for r in rs))),
        ])
        dep_groups = self._wrapper((mkdict(*g) for g in self._stream))

        ret = { "Belege-Gruppe": dep_groups }
        ret.update(self._extra)
        return ret

    def addExtra(self, key, value):
        self._extra[key] = value

class JSONExporter(DEPExporter):
    """
    Exports a DEP to JSON format. The pretty parameter is used to determine if
    indentation is used in the final JSON. The output of the export() method is
    a generator which yields a string at every iteration. The strings
    concatenated form the final JSON form.
    """

    def __init__(self, dep_stream, pretty=True):
        super(JSONExporter, self).__init__(dep_stream, FakeListIterator)
        if pretty:
            self._encoder = json.JSONEncoder(sort_keys=False, indent=2)
        else:
            self._encoder = json.JSONEncoder(sort_keys=False)

    def export(self):
        stream = super(JSONExporter, self).export()
        return self._encoder.iterencode(stream)

# Supports no certs and no groups
class CSVExporter(DEPExporterI):
    """
    Exports a DEP to CSV format. The output of the export() method is a
    generator which yields a string at every iteration. The strings concatenated
    form the final CSV form.
    """

    def __init__(self, dep_stream):
        self._stream = dep_stream

    def export(self):
        yield 'Alg+ZDA;Register ID;Receipt ID;Date+Time;Sum A;Sum B;Sum C;Sum D;Sum E;Turnover Counter;Cert. Serial;Chaining Value;Signature'
        for g in self._stream:
            for r in g[0]:
                yield ('\n' + r[0].toCSV(r[1]))
            g = None

    def addExtra(self, key, value):
        pass
