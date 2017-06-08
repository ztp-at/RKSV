#!/usr/bin/env python2.7

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

from builtins import int
from builtins import range

import kivy
kivy.require('1.9.0')

import base64 
import configparser
import os

from requests.exceptions import RequestException
from PIL import Image

from kivy.adapters.dictadapter import DictAdapter
from kivy.app import App
from kivy.core.window import Window
from kivy.clock import mainthread, Clock
from kivy.properties import ObjectProperty, DictProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.listview import CompositeListItem, ListItemButton, ListItemLabel
from kivy.uix.modalview import ModalView
from kivy.uix.popup import Popup
from kivy.uix.selectableview import SelectableView
from kivy.uix.treeview import TreeView, TreeViewNode, TreeViewLabel
from kivy.utils import platform

if platform == 'android':
    from android import activity
    from cStringIO import StringIO
    from jnius import autoclass
    Activity = autoclass('android.app.Activity')
    CompressFormat = autoclass('android.graphics.Bitmap$CompressFormat')
    ByteArrayOutputStream = autoclass('java.io.ByteArrayOutputStream')
    Intent = autoclass('android.content.Intent')
    MediaStore = autoclass('android.provider.MediaStore')
    PythonActivity = autoclass('org.kivy.android.PythonActivity')
    Locale = autoclass('java.util.Locale')
    Env = autoclass('android.os.Environment')
    PM = autoclass('android.content.pm.PackageManager')

    import os
    os.environ['LANG'] = Locale.getDefault().toString()

    __use_threads = True
else:
    __use_threads = False

import algorithms
import img_decode
import key_store
import receipt
import utils
import verify_receipt
import verify

if __use_threads:
    # This code blatantly copied from https://stackoverflow.com/a/325528
    import ctypes
    import inspect
    import threading

    def _async_raise(tid, exctype):
        '''Raises an exception in the threads with id tid'''
        if not inspect.isclass(exctype):
            raise TypeError("Only types can be raised (not instances)")
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid,
                ctypes.py_object(exctype))
        if res == 0:
            raise ValueError("invalid thread id")
        elif res != 1:
            # "if it returns a number greater than one, you're in trouble,
            # and you should call it again with exc=NULL to revert the effect"
            ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, 0)
            raise SystemError("PyThreadState_SetAsyncExc failed")

    class ThreadWithExc(threading.Thread):
        '''A thread class that supports raising exception in the thread from
           another thread.
        '''
        def _get_my_tid(self):
            """determines this (self's) thread id
            CAREFUL : this function is executed in the context of the caller
            thread, to get the identity of the thread represented by this
            instance.
            """
            if not self.isAlive():
                raise threading.ThreadError("the thread is not active")

            # do we have it cached?
            if hasattr(self, "_thread_id"):
                return self._thread_id

            # no, look for it in the _active dict
            for tid, tobj in threading._active.items():
                if tobj is self:
                    self._thread_id = tid
                    return tid

            # TODO: in python 2.6, there's a simpler way to do : self.ident

            raise AssertionError("could not determine the thread's id")

        def raiseExc(self, exctype):
            """Raises the given exception type in the context of this thread.
            If the thread is busy in a system call (time.sleep(),
            socket.accept(), ...), the exception is simply ignored.
            If you are sure that your exception should terminate the thread,
            one way to ensure that it works is:
                t = ThreadWithExc( ... )
                ...
                t.raiseExc( SomeException )
                while t.isAlive():
                    time.sleep( 0.1 )
                    t.raiseExc( SomeException )
            If the exception is to be caught by the thread, you need a way to
            check that your thread has caught it.
            CAREFUL : this function is executed in the context of the
            caller thread, to raise an excpetion in the context of the
            thread represented by this instance.
            """
            _async_raise( self._get_my_tid(), exctype )

    # original work starts here, donut steel
    import copy

    def __thread_apply__(f, args, callback):
        try:
            callback(f(*args))
        except threading.ThreadError:
            pass

    def __thread_map__(f, iterable, callback):
        try:
            callback(map(f, iterable))
        except threading.ThreadError:
            pass

    class ThreadPool(object):
        def __init__(self, nprocs, init = None, initargs = ()):
            # Ignore all args, this is not a real pool.
            self._thread = None

        def terminate(self):
            try:
                if self._thread:
                    self._thread.raiseExc(threading.ThreadError)
            except (threading.ThreadError, TypeError, ValueError, SystemError):
                pass

            self._thread = None

        def join(self):
            pass

        def apply_async(self, f, args, callback):
            targs = copy.deepcopy(args)
            self._thread = ThreadWithExc(target = __thread_apply__,
                    args = (f, targs, callback))
            self._thread.start()

        def map_async(self, f, iterable, callback):
            titerable = copy.deepcopy(iterable)
            self._thread = ThreadWithExc(target = __thread_map__,
                    args = (f, titerable, callback))
            self._thread.start()

    PoolClass = ThreadPool
    Nprocs = 1
else:
    import multiprocessing

    PoolClass = multiprocessing.Pool
    Nprocs = multiprocessing.cpu_count()

def getModalView():
    return ModalView(size_hint=(1, None), pos_hint={'top': 1},
            height=Window.height - Window.keyboard_height,
            auto_dismiss=False)

def getPopup(title, content):
    return Popup(title=title, content=content,
            size_hint=(0.9, None), pos_hint={'top': 1},
            height=Window.height - Window.keyboard_height)

class ErrorDialog(FloatLayout):
    exception = ObjectProperty(None)
    cancel = ObjectProperty(None)

def displayError(ex):
    content = ErrorDialog(exception=ex)
    popup = getPopup(_("Error"), content)
    content.cancel = popup.dismiss
    popup.open()

class LoadDialog(FloatLayout):
    load = ObjectProperty(None)
    cancel = ObjectProperty(None)

class SaveDialog(FloatLayout):
    save = ObjectProperty(None)
    text_input = ObjectProperty(None)
    cancel = ObjectProperty(None)

class SingleValueDialog(FloatLayout):
    receive_value = ObjectProperty(None)
    text_input = ObjectProperty(None)
    cancel = ObjectProperty(None)

class TreeViewButton(Button, TreeViewNode):
    pass

class TreeViewReceiptButton(TreeViewButton):
    group_id = ObjectProperty(None)
    receipt_id = ObjectProperty(None)

class TreeViewKeyButton(TreeViewButton):
    key_id = ObjectProperty(None)
    key = ObjectProperty(None)

class ViewReceiptItem(GridLayout, SelectableView):
    item_name = ObjectProperty(None)
    item_value = ObjectProperty(None)

def verifyReceiptTask(rec, prefix, store):
    try:
        rv = verify_receipt.ReceiptVerifier.fromKeyStore(store)
        rv.verify(rec, prefix)
        return None
    except receipt.ReceiptException as e:
        return e

class ViewReceiptWidget(BoxLayout):
    adapter = ObjectProperty(None)
    cancel = ObjectProperty(None)
    verify_button = ObjectProperty(None)
    decrypt_button = ObjectProperty(None)
    aes_input = ObjectProperty(None)

    def dismissPopup(self):
        self._popup.dismiss()

    def __init__(self, receipt, algorithmPrefix, isValid, key, **kwargs):
        self._init_key = key
        self._receipt = receipt
        self._key = None
        self._algorithmPrefix = algorithmPrefix
        self._is_valid = isValid
        self._popup = None

        convert = lambda row_index, rec: \
                { 'item_name': rec[0]
                , 'item_value': rec[1]
                }
        keys = list(range(1, 14))
        
        self.adapter = DictAdapter(sorted_keys=keys,
                data=dict(), args_converter=convert,
                cls=ViewReceiptItem)

        super(ViewReceiptWidget, self).__init__(**kwargs)

        if receipt.isDummy() or receipt.isReversal():
            self.decrypt_button.disabled = True

        if isValid:
            self.verify_button.text = _('Valid Signature')
            self.verify_button.disabled = True
            self.verify_button.background_color = (0, 1, 0, 1)

        if receipt.isSignedBroken():
            self.verify_button.text = _('No Signature')
            self.verify_button.disabled = True

            if not receipt.isDummy() and not receipt.isReversal() and receipt.isNull():
                def showReceiptError(instance):
                    displayError(
                            verify_receipt.UnsignedNullReceiptException(
                                receipt.receiptId))
                Clock.schedule_once(showReceiptError, 0)
        
        self.updateView()

    def firstDisplay(self, inst):
        self.setKey(self._init_key)

    def updateView(self):
        receipt = self._receipt
        algorithmPrefix = self._algorithmPrefix
        key = self._key

        turnoverCounter = receipt.encTurnoverCounter
        if receipt.isDummy():
            turnoverCounter = 'TRA'
        elif receipt.isReversal():
            turnoverCounter = 'STO'
        elif key and (algorithmPrefix in algorithms.ALGORITHMS):
            algorithm = algorithms.ALGORITHMS[algorithmPrefix]
            turnoverCounter = receipt.decryptTurnoverCounter(key, algorithm)
            turnoverCounter = str(float(turnoverCounter) / 100)

        signature = receipt.signature
        if receipt.isSignedBroken():
            signature = _('Signature system broken')

        maps =  { 1: ( _('ZDA ID'), algorithmPrefix + '-' + receipt.zda )
                , 2: ( _('Cash Register ID'), receipt.registerId )
                , 3: ( _('Receipt ID'), receipt.receiptId )
                , 4: ( _('Timestamp'), receipt.dateTime.strftime("%Y-%m-%dT%H:%M:%S") )
                , 5: ( _('Sum Tax Normal'), str(receipt.sumA) )
                , 6: ( _('Sum Tax Reduced 1'), str(receipt.sumB) )
                , 7: ( _('Sum Tax Reduced 2'), str(receipt.sumC) )
                , 8: ( _('Sum Tax Zero'), str(receipt.sumD) )
                , 9: ( _('Sum Tax Special'), str(receipt.sumE) )
                ,10: ( _('Turnover Counter'), turnoverCounter )
                ,11: ( _('Certificate Serial/Key ID'), receipt.certSerial )
                ,12: ( _('Chaining Value'), receipt.previousChain )
                ,13: ( _('Signature'), signature )
                }
        self.adapter.data = maps

    def verify(self):
        self.verify_button.text = _('Verifying...')
        self.verify_button.disabled = True

        App.get_running_app().pool.apply_async(verifyReceiptTask,
                (self._receipt, self._algorithmPrefix,
                    App.get_running_app().keyStore), callback=self.verifyCb)

    @mainthread
    def verifyCb(self, result):
        if result:
            self.verify_button.text = _('Verify')
            self.verify_button.disabled = False

            displayError(result)

        else:
            self.verify_button.text = _('Valid Signature')
            self.verify_button.disabled = True
            self.verify_button.background_color = (0, 1, 0, 1)

    def decrypt(self):
        if self.aes_input.text != '':
            self.setKey(self.aes_input.text)
        else:
            self.loadAES()

    def loadAES(self):
        content = LoadDialog(load=self.loadAESCb,
                cancel=self.dismissPopup)
        self._popup = getPopup(_("Load AES Key"), content)
        self._popup.open()

    def loadAESCb(self, path, filename):
        if not filename or len(filename) < 1:
            return

        key = None
        try:
            full = os.path.join(path, filename[0])
            with open(full) as f:
                if full.endswith(".json"):
                    jsonAES = utils.readJsonStream(f)
                    key = jsonAES["base64AESKey"]
                else:
                    key = f.read()

            App.get_running_app().curSearchPath = path
        except (IOError, UnicodeDecodeError, ValueError) as e:
            displayError(e)
        except KeyError:
            displayError(_("Malformed crypto container"))

        self.dismissPopup()
        self.setKey(key)

    def setKey(self, key):
        self._key = None
        try:
            if key and key != '':
                self.aes_input.text = key
                k = base64.b64decode(key.encode('utf-8'))
                if self._algorithmPrefix not in algorithms.ALGORITHMS:
                    raise receipt.UnknownAlgorithmException(
                            self._receipt.receiptId)
                algorithm = algorithms.ALGORITHMS[self._algorithmPrefix]
                if not algorithm.verifyKey(k):
                    raise Exception(_("Invalid key."))
                self._key = k
        except Exception as e:
            self.aes_input.text = ''
            displayError(e)

        if self._key:
            self.decrypt_button.disabled = True
            self.updateView()

CAPTURE_IMAGE_ACTIVITY_REQUEST_CODE = 7
class VerifyReceiptWidget(BoxLayout):
    receiptInput = ObjectProperty(None)
    loadLayout = ObjectProperty(None)
    buttons = DictProperty(None)
    _input_type = 'JWS'

    def __init__(self, **kwargs):
        super(VerifyReceiptWidget, self).__init__(**kwargs)
        if platform == 'android':
            pm = PythonActivity.mActivity.getPackageManager()
            if not pm.hasSystemFeature(PM.FEATURE_CAMERA):
                return

            def addCamButton(instance):
                self.loadLayout.add_widget(Button(size_hint=(None, 1),
                        text='C', on_press=self.takePicture))
            Clock.schedule_once(addCamButton, 0)
            activity.bind(on_activity_result=self.takePictureCb)

    def dismissPopup(self):
        self._popup.dismiss()

    def takePicture(self, button):
        intent = Intent()
        intent.setAction(MediaStore.ACTION_IMAGE_CAPTURE)
        PythonActivity.mActivity.startActivityForResult(intent,
            CAPTURE_IMAGE_ACTIVITY_REQUEST_CODE)

    @mainthread
    def takePictureCb(self, requestCode, resultCode, intent):
        if requestCode != CAPTURE_IMAGE_ACTIVITY_REQUEST_CODE:
            return

        if resultCode != Activity.RESULT_OK:
            displayError(_("No image taken."))
            return

        stream = ByteArrayOutputStream()
        done = intent.getExtras().get('data').compress(
            CompressFormat.PNG, 100, stream)
        stream.close()

        if not done:
            displayError(_("Failed to compress image."))
            return
        ba = stream.toByteArray()

        stream = None
        img = None
        try:
            stream = StringIO(str(bytearray(ba)))
            img = Image.open(stream)
        except IOError as e:
            if stream:
                stream.close()
            displayError(e)
            return

        codes = img_decode.read_qr_codes(img)
        stream.close()

        if len(codes) < 1:
            displayError(_("No QR codes found."))
        else:
            self.receiptInput.text = codes[0]
            self.selectInputType('QR')

    def loadReceipt(self):
        content = LoadDialog(load=self.loadReceiptCb,
                cancel=self.dismissPopup)
        self._popup = getPopup(_("Load Receipt"), content)
        self._popup.open()

    def loadReceiptCb(self, path, filename):
        if not filename or len(filename) < 1:
            return

        full = os.path.join(path, filename[0])
        try:
            with open(full, mode='rb') as f:
                img = Image.open(f)
                codes = img_decode.read_qr_codes(img)
                if len(codes) < 1:
                    displayError(_("No QR codes found."))
                else:
                    self.receiptInput.text = codes[0]
                    self.selectInputType('QR')

            App.get_running_app().curSearchPath = path
        except IOError:
            try:
                with open(full) as f:
                    self.receiptInput.text = f.read().strip()
            except (IOError, UnicodeDecodeError) as e:
                displayError(e)

        self.dismissPopup()

    def selectInputType(self, inputType):
        if self._input_type == inputType:
            return

        self._input_type = inputType
        for b in self.buttons.values():
            b.state = 'normal'
        self.buttons[inputType].state = 'down'

    def viewReceipt(self):
        try:
            rec = None
            prefix = None
            if (self._input_type == 'JWS'):
                rec, prefix = receipt.Receipt.fromJWSString(self.receiptInput.text)
            elif (self._input_type == 'QR'):
                rec, prefix = receipt.Receipt.fromBasicCode(self.receiptInput.text)
            elif (self._input_type == 'OCR'):
                rec, prefix = receipt.Receipt.fromOCRCode(self.receiptInput.text)
            elif (self._input_type == 'URL'):
                urlHash = utils.getURLHashFromURL(self.receiptInput.text)
                basicCode = utils.getBasicCodeFromURL(self.receiptInput.text)

                rec, prefix = receipt.Receipt.fromBasicCode(basicCode)

                if prefix not in algorithms.ALGORITHMS:
                    raise receipt.UnknownAlgorithmException(rec.receiptId)
                algorithm = algorithms.ALGORITHMS[prefix]

                verify_receipt.verifyURLHash(rec, algorithm, urlHash)
            else:
                return

            content = ViewReceiptWidget(rec, prefix, False, None,
                    cancel=self.dismissPopup)
            self._popup = getModalView()
            self._popup.add_widget(content)
            self._popup.open()
        except (receipt.ReceiptException, RequestException) as e:
            displayError(e)

def verifyDEP_prepare_Task(dep, store, key, nprocs):
    try:
        inargs, usedRecIds = verify.verifyParsedDEP_prepare(dep, store, key,
                None, None, nprocs)
        return None, inargs
    except (receipt.ReceiptException, verify.DEPException) as e:
        return e, None

def verifyDEP_main_Task(args):
    try:
        rState, usedRecIds = verify.verifyGroupsWithVerifiersTuple(args)
        return None, usedRecIds
    except (receipt.ReceiptException, verify.DEPException) as e:
        return e, None

def verifyDEP_finalize_Task(outUsedRecIds, usedRecIds):
    try:
        mergedUsedRecIds = verify.verifyParsedDEP_finalize(outUsedRecIds,
                usedRecIds)
        return None, mergedUsedRecIds
    except (receipt.ReceiptException, verify.DEPException) as e:
        return e, None

# TODO: add a visual way to determine where an error happened?
class VerifyDEPWidget(BoxLayout):
    treeView = ObjectProperty(None)
    aesInput = ObjectProperty(None)
    verify_button = ObjectProperty(None)

    _verifying = False
    _verified = False

    def addCert(self, btn):
        pubKey = btn.key.public_key()
        App.get_running_app().keyStore.putKey(btn.key_id, pubKey, btn.key)
        App.get_running_app().updateKSWidget()

    def viewReceipt(self, btn):
        try:
            recs, cert, cert_list = self.dep[btn.group_id]
            jws = recs[btn.receipt_id]
            rec, prefix = receipt.Receipt.fromJWSString(jws)

            self._receipt_view = getModalView()
            content = ViewReceiptWidget(rec, prefix, self._verified,
                    self.aesInput.text, cancel=self._receipt_view.dismiss)
            self._receipt_view.add_widget(content)
            self._receipt_view.bind(on_open=content.firstDisplay)
            self._receipt_view.open()
        except receipt.ReceiptException as e:
            displayError(e)

    def clearDEPDisplay(self):
        while len(self.treeView.root.nodes) > 0:
            for n in self.treeView.iterate_all_nodes():
                self.treeView.remove_node(n)

    def updateDEPDisplay(self):
        tv = self.treeView

        self.clearDEPDisplay()

        try:
            groupIdx = 1
            for recs, cert, cert_list in self.dep:
                groupNode = tv.add_node(TreeViewLabel(
                    text=(_('Group %d') % groupIdx)))

                certNode = tv.add_node(TreeViewLabel(
                    text='Signaturzertifikat'), groupNode)
                chainNode = tv.add_node(TreeViewLabel(
                    text='Zertifizierungsstellen'), groupNode)
                receiptsNode = tv.add_node(TreeViewLabel(
                    text='Belege-kompakt'), groupNode)

                if cert:
                    serial = key_store.numSerialToKeyId(cert.serial)
                    tv.add_node(TreeViewKeyButton(
                        text=_('Serial: ') + serial,
                        key_id=serial, key=cert,
                        on_press=self.addCert), certNode)

                for cert in cert_list:
                    serial = key_store.numSerialToKeyId(cert.serial)
                    tv.add_node(TreeViewKeyButton(
                        text=_('Serial: ') + serial,
                        key_id=serial, key=cert,
                        on_press=self.addCert), chainNode)

                receiptIdx = 0
                for cr in recs:
                    jws = verify.expandDEPReceipt(cr)
                    rec, prefix = receipt.Receipt.fromJWSString(jws)
                    tv.add_node(TreeViewReceiptButton(text=rec.receiptId,
                        group_id=groupIdx - 1, receipt_id=receiptIdx,
                        on_press=self.viewReceipt), receiptsNode)
                    receiptIdx += 1

                groupIdx += 1

            return True

        except receipt.ReceiptException as e:
            displayError(e)

        self.clearDEPDisplay()
        return False

    def verifyAbort(self):
        App.get_running_app().killBackgroundProcesses()

        self._verifying = False
        self._verified = False
        self.verify_button.disabled = False
        self.verify_button.text = _('Verify')
        self.verify_button.background_color = (1, 1, 1, 1)

    def verify(self):
        if self._verifying:
            self.verifyAbort()
            return

        key = None
        try:
            k = self.aesInput.text
            if k and k != '':
                key = base64.b64decode(k.encode('utf-8'))
        except Exception as e:
            self.aesInput.text = ''
            displayError(e)
            return

        self._verifying = True
        self.verify_button.text = _('Verifying...')

        App.get_running_app().pool.apply_async(verifyDEP_prepare_Task,
                (self.dep, App.get_running_app().keyStore, key,
                    App.get_running_app().nprocs),
                callback = self.verifyDEP_prepare_Cb)

    @mainthread
    def verifyDEP_prepare_Cb(self, result):
        if not self._verifying:
            return

        if result[0]:
            self._verifying = False
            self.verify_button.text = _('Verify')
            displayError(result[0])

        else:
            App.get_running_app().pool.map_async(verifyDEP_main_Task,
                    result[1], callback = self.verifyDEP_main_Cb)

    def verifyDEP_main_Cb(self, result):
        if not self._verifying:
            return

        outUsedRecIds = list()
        for r in result:
            if r[0]:
                self._verifying = False
                self.verify_button.text = _('Verify')
                displayError(r[0])
                return
            outUsedRecIds.append(r[1])

        App.get_running_app().pool.apply_async(verifyDEP_finalize_Task,
                (outUsedRecIds, set()), callback =
                self.verifyDEP_finalize_Cb)

    @mainthread
    def verifyDEP_finalize_Cb(self, result):
        if not self._verifying:
            return

        self._verifying = False
        if result[0]:
            self.verify_button.text = _('Verify')
            displayError(result[0])

        else:
            self._verified = True
            self.verify_button.disabled = True
            self.verify_button.text = _('Valid DEP')
            self.verify_button.background_color = (0, 1, 0, 1)

    def dismissPopup(self):
        self._popup.dismiss()

    def loadDEP(self):
        content = LoadDialog(load=self.loadDEPCb,
                cancel=self.dismissPopup)
        self._popup = getPopup(_("Load DEP"), content)
        self._popup.open()

    def loadDEPCb(self, path, filename):
        if not filename or len(filename) < 1:
            return

        try:
            with open(os.path.join(path, filename[0])) as f:
                jsonDEP = utils.readJsonStream(f)
                self.dep = verify.parseDEPAndGroups(jsonDEP)

            App.get_running_app().curSearchPath = path
        except (IOError, UnicodeDecodeError, ValueError,
                verify.DEPException) as e:
            displayError(e)
            self.dismissPopup()
            return

        self.verifyAbort()
        if not self.updateDEPDisplay():
            self.verify_button.disabled = True
            self.dep = None

        self.dismissPopup()

    def loadAES(self):
        content = LoadDialog(load=self.loadAESCb,
                cancel=self.dismissPopup)
        self._popup = getPopup(_("Load AES Key"), content)
        self._popup.open()

    def loadAESCb(self, path, filename):
        if not filename or len(filename) < 1:
            return

        try:
            full = os.path.join(path, filename[0])
            with open(full) as f:
                if full.endswith(".json"):
                    jsonAES = utils.readJsonStream(f)
                    self.aesInput.text = jsonAES["base64AESKey"]
                else:
                    self.aesInput.text = f.read()

            App.get_running_app().curSearchPath = path
        except (IOError, UnicodeDecodeError, ValueError) as e:
            displayError(e)
        except KeyError:
            displayError(_("Malformed crypto container"))

        self.dismissPopup()

class KeyStoreWidget(BoxLayout):
    pubKeyGroup = ObjectProperty(None)
    certGroup = ObjectProperty(None)
    treeView = ObjectProperty(None)

    def on_treeView(self, instance, value):
        tv = self.treeView
        self.pubKeyGroup = tv.add_node(TreeViewButton(text=_('Public Keys'),
                on_press=self.addPubKey))
        self.certGroup = tv.add_node(TreeViewButton(text=_('Certificates'),
                on_press=self.addCert))

        App.get_running_app().ksWidget = self

    def buildKSTree(self):
        if not self.treeView:
            return
        if not self.pubKeyGroup or not self.certGroup:
            return

        tv = self.treeView

        while len(self.pubKeyGroup.nodes) > 0:
            iterator = iter(tv.iterate_all_nodes(node=self.pubKeyGroup))
            next(iterator)
            for n in iterator:
                tv.remove_node(n)

        while len(self.certGroup.nodes) > 0:
            iterator = iter(tv.iterate_all_nodes(node=self.certGroup))
            next(iterator)
            for n in iterator:
                tv.remove_node(n)

        ks = App.get_running_app().keyStore
        for kid in ks.getKeyIds():
            cert = ks.getCert(kid)
            if cert:
                tv.add_node(TreeViewKeyButton(
                    text=_('Serial: ') + kid,
                    on_press=self.delKey,
                    key_id=kid), self.certGroup)
            else:
                tv.add_node(TreeViewKeyButton(
                    text=_('Key ID: ') + kid,
                    on_press=self.delKey,
                    key_id=kid), self.pubKeyGroup)

    def delKey(self, btn):
        App.get_running_app().keyStore.delKey(btn.key_id)
        self.buildKSTree()

    def dismissPopup(self):
        self._popup.dismiss()

    def addPubKey(self, btn):
        content = LoadDialog(load=self.addPubKeyCbKey, cancel=self.dismissPopup)
        self._popup = getPopup(_("Load PEM Public Key"), content)
        self._popup.open()

    def addCert(self, btn):
        content = LoadDialog(load=self.addCertCb, cancel=self.dismissPopup)
        self._popup = getPopup(_("Load PEM Certificate"), content)
        self._popup.open()

    def addPubKeyCbKey(self, path, filename):
        if not filename or len(filename) < 1:
            return

        try:
            with open(os.path.join(path, filename[0])) as f:
                self._tmpPubKey = f.read()

            App.get_running_app().curSearchPath = path
        except (IOError, UnicodeDecodeError) as e:
            displayError(e)
            self.dismissPopup()
            return

        content = SingleValueDialog(receive_value=self.addPubKeyCbId,
                cancel=self.dismissPopup)

        self.dismissPopup()
        self._popup = getPopup(_("Enter Public Key ID"), content)
        self._popup.open()

    def addPubKeyCbId(self, keyId):
        try:
            App.get_running_app().keyStore.putPEMKey(keyId, self._tmpPubKey)
        except ValueError as e:
            displayError(e)

        self.dismissPopup()
        self.buildKSTree()

    def addCertCb(self, path, filename):
        if not filename or len(filename) < 1:
            return

        try:
            with open(os.path.join(path, filename[0])) as f:
                App.get_running_app().keyStore.putPEMCert(f.read())

            App.get_running_app().curSearchPath = path
        except (IOError, UnicodeDecodeError, ValueError) as e:
            displayError(e)

        self.dismissPopup()
        self.buildKSTree()

    def importKeyStore(self):
        content = LoadDialog(load=self.importKeyStoreCb,
                cancel=self.dismissPopup)
        self._popup = getPopup(_("Load Key Store"), content)
        self._popup.open()

    def exportKeyStore(self):
        content = SaveDialog(save=self.exportKeyStoreCb,
                cancel=self.dismissPopup)
        self._popup = getPopup(_("Save Key Store"), content)
        self._popup.open()

    def importKeyStoreCb(self, path, filename):
        if not filename or len(filename) < 1:
            return

        try:
            full = os.path.join(path, filename[0])
            if full.endswith(".json"):
                with open(full) as f:
                    jsonKS = utils.readJsonStream(f)
                    App.get_running_app().keyStore = \
                            key_store.KeyStore.readStoreFromJson(jsonKS)
            else:
                config = configparser.RawConfigParser()
                config.optionxform = str
                with open(full) as f:
                    config.readfp(f)
                App.get_running_app().keyStore = \
                        key_store.KeyStore.readStore(config)

            App.get_running_app().curSearchPath = path
        except (IOError, UnicodeDecodeError, ValueError,
                configparser.Error) as e:
            displayError(e)
        except KeyError:
            displayError(_("Malformed crypto container"))

        self.dismissPopup()
        self.buildKSTree()

    def exportKeyStoreCb(self, path, filename):
        if not filename:
            return

        config = configparser.RawConfigParser()
        config.optionxform = str
        App.get_running_app().keyStore.writeStore(config)
        try:
            with open(os.path.join(path, filename), 'w') as f:
                config.write(f)

            App.get_running_app().curSearchPath = path
        except IOError as e:
            displayError(e)

        self.dismissPopup()

class MainWidget(BoxLayout):
    def __init__(self, **kwargs):
        super(MainWidget, self).__init__(**kwargs)
        if platform == 'android':
            self.size_hint_y = None

import signal
def workerInit():
    # Restore handler for SIGTERM so we can actually kill the workers.
    signal.signal(signal.SIGTERM, signal.SIG_DFL)

class RKToolApp(App):
    keyStore = key_store.KeyStore()
    ksWidget = None
    curSearchPath = Env.getExternalStorageDirectory().getAbsolutePath() if platform == 'android' else os.getcwd()

    def __init__(self, nprocs):
        super(RKToolApp, self).__init__()
        self.pool = None
        self.nprocs = nprocs

    def killBackgroundProcesses(self):
        self.pool.terminate()
        self.pool.join()
        self.pool = PoolClass(self.nprocs, workerInit)

    def on_pause(self):
        return True

    def on_resume(self):
        pass

    def on_start(self):
        self.pool = PoolClass(self.nprocs, workerInit)

    def on_stop(self):
        self.pool.terminate()
        self.pool.join()

    def updateKSWidget(self):
        if self.ksWidget:
            self.ksWidget.buildKSTree()

    def updateHeight(self, instance, value):
        for c in Window.children:
            c.height = Window.height - Window.keyboard_height

    def build(self):
        Window.bind(keyboard_height=self.updateHeight)
        if platform == 'android':
            return MainWidget()

        # the dreaded splash screen code
        from kivy.uix.screenmanager import NoTransition, ScreenManager, Screen
        from kivy.uix.image import Image

        sm = ScreenManager(transition=NoTransition())

        splashScr = Screen(name='SplashScreen')
        splashScr.add_widget(Image(source='misc/splash-desktop.png'))
        sm.add_widget(splashScr)

        mainScr = Screen(name='MainScreen')
        mainScr.add_widget(MainWidget())
        sm.add_widget(mainScr)

        def switchToMainScr(instance):
            sm.current = 'MainScreen'

        Clock.schedule_once(switchToMainScr, 3)

        return sm

if __name__ == '__main__':
    import gettext
    gettext.install('rktool', './lang', True)

    if platform != 'android':
        from kivy.config import Config
        Config.set('graphics', 'width', '800')
        Config.set('graphics', 'height', '600')

    RKToolApp(Nprocs).run()
