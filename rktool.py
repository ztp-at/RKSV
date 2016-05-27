#!/usr/bin/python2

from builtins import int

import kivy
kivy.require('1.9.0')

import base64 
import configparser
import copy
import json
import os
import threading
import utils

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
    PythonActivity = autoclass('org.renpy.android.PythonActivity')

import algorithms
import img_decode
import key_store
import receipt
import verify_receipt
import verify

# This code blatantly copied from https://stackoverflow.com/a/325528
import ctypes
import inspect

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
    popup = getPopup("Error", content)
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
            self.verify_button.text = 'Valid Signature'
            self.verify_button.disabled = True

        if receipt.isSignedBroken():
            self.verify_button.text = 'No Signature'
            self.verify_button.disabled = True
        
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
            signature = 'Signature system broken'

        maps =  { 1: ( 'ZDA ID', algorithmPrefix + '-' + receipt.zda )
                , 2: ( 'Cash Register ID', receipt.registerId )
                , 3: ( 'Receipt ID', receipt.receiptId )
                , 4: ( 'Timestamp', receipt.dateTime.strftime("%Y-%m-%dT%H:%M:%S") )
                , 5: ( 'Sum Tax Normal', str(receipt.sumA) )
                , 6: ( 'Sum Tax Reduced 1', str(receipt.sumB) )
                , 7: ( 'Sum Tax Reduced 2', str(receipt.sumC) )
                , 8: ( 'Sum Tax Zero', str(receipt.sumD) )
                , 9: ( 'Sum Tax Special', str(receipt.sumE) )
                ,10: ( 'Turnover Counter', turnoverCounter )
                ,11: ( 'Certificate Serial/Key ID', receipt.certSerial )
                ,12: ( 'Chaining Value', receipt.previousChain )
                ,13: ( 'Signature', signature )
                }
        self.adapter.data = maps

    def verify(self):
        self.verify_button.text = 'Verifying...'
        self.verify_button.disabled = True

        rec = copy.deepcopy(self._receipt)
        prefix = copy.deepcopy(self._algorithmPrefix)
        store = copy.deepcopy(App.get_running_app().keyStore)

        ThreadWithExc(target=self.verifyReceiptTask,
                args=(rec, prefix, store,)).start()

    @mainthread
    def verifyCb(self, result):
        if result:
            self.verify_button.text = 'Verify'
            self.verify_button.disabled = False

            displayError(result)

        else:
            self.verify_button.text = 'Valid Signature'
            self.verify_button.disabled = True

    def verifyReceiptTask(self, rec, prefix, store):
        try:
            rv = verify_receipt.ReceiptVerifier.fromKeyStore(store)
            rv.verify(rec, prefix)
            self.verifyCb(None)
        except receipt.ReceiptException as e:
            self.verifyCb(e)

    def decrypt(self):
        if self.aes_input.text != '':
            self.setKey(self.aes_input.text)
        else:
            self.loadAES()

    def loadAES(self):
        content = LoadDialog(load=self.loadAESCb,
                cancel=self.dismissPopup)
        self._popup = getPopup("Load AES Key", content)
        self._popup.open()

    def loadAESCb(self, path, filename):
        if not filename or len(filename) < 1:
            return

        key = None
        try:
            full = os.path.join(path, filename[0])
            with open(full) as f:
                if full.endswith(".json"):
                    jsonAES = json.loads(f.read())
                    key = jsonAES["base64AESKey"]
                else:
                    key = f.read()
        except (IOError, ValueError) as e:
            displayError(e)
        except KeyError:
            displayError("Malformed crypto container")

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
                            self._receipt.toJWSString(
                                self._algorithmPrefix))
                algorithm = algorithms.ALGORITHMS[self._algorithmPrefix]
                if not algorithm.verifyKey(k):
                    raise Exception("Invalid key.")
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
            displayError("No image taken.")
            return

        stream = ByteArrayOutputStream()
        done = intent.getExtras().get('data').compress(
            CompressFormat.PNG, 100, stream)
        stream.close()

        if not done:
            displayError("Failed to compress image.")
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
            displayError("No QR codes found.")
        else:
            self.receiptInput.text = codes[0]
            self.selectInputType('QR')

    def loadReceipt(self):
        content = LoadDialog(load=self.loadReceiptCb,
                cancel=self.dismissPopup)
        self._popup = getPopup("Load Receipt", content)
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
                    displayError("No QR codes found.")
                else:
                    self.receiptInput.text = codes[0]
                    self.selectInputType('QR')
        except IOError:
            try:
                with open(full) as f:
                    self.receiptInput.text = f.read().strip()
            except IOError as e:
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
                    raise receipt.UnknownAlgorithmException(basicCode)
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

# TODO: add a visual way to determine where an error happened?
class VerifyDEPWidget(BoxLayout):
    treeView = ObjectProperty(None)
    aesInput = ObjectProperty(None)
    verify_button = ObjectProperty(None)

    _verifying = False
    _verified = False
    _verifyThread = None

    def addCert(self, btn):
        pubKey = btn.key.public_key()
        App.get_running_app().keyStore.putKey(btn.key_id, pubKey, btn.key)
        App.get_running_app().updateKSWidget()

    def viewReceipt(self, btn):
        try:
            group = self._jsonDEP['Belege-Gruppe'][btn.group_id]
            jws = group['Belege-kompakt'][btn.receipt_id]
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
            for group in self._jsonDEP['Belege-Gruppe']:
                groupNode = tv.add_node(TreeViewLabel(
                    text=('Gruppe %d' % groupIdx)))

                certNode = tv.add_node(TreeViewLabel(
                    text='Signaturzertifikat'), groupNode)
                chainNode = tv.add_node(TreeViewLabel(
                    text='Zertifizierungsstellen'), groupNode)
                receiptsNode = tv.add_node(TreeViewLabel(
                    text='Belege-kompakt'), groupNode)

                pem = group['Signaturzertifikat']
                if pem:
                    cert = utils.loadCert(utils.addPEMCertHeaders(pem))
                    serial = "%x" % cert.serial
                    tv.add_node(TreeViewKeyButton(
                        text=serial,
                        key_id=serial, key=cert,
                        on_press=self.addCert), certNode)

                for pem in group['Zertifizierungsstellen']:
                    cert = utils.loadCert(utils.addPEMCertHeaders(pem))
                    serial = "%x" % cert.serial
                    tv.add_node(TreeViewKeyButton(
                        text=serial,
                        key_id=serial, key=cert,
                        on_press=self.addCert), chainNode)

                receiptIdx = 0
                for jws in group['Belege-kompakt']:
                    rec, prefix = receipt.Receipt.fromJWSString(jws)
                    tv.add_node(TreeViewReceiptButton(text=rec.receiptId,
                        group_id=groupIdx - 1, receipt_id=receiptIdx,
                        on_press=self.viewReceipt), receiptsNode)
                    receiptIdx += 1

                groupIdx += 1

            return True

        except ValueError as e:
            displayError(e)
        except receipt.ReceiptException as e:
            displayError(e)
        except KeyError as e:
            displayError("Malformed DEP")

        self.clearDEPDisplay()
        return False

    def verifyAbort(self):
        try:
            if self._verifyThread:
                self._verifyThread.raiseExc(threading.ThreadError)
        except (threading.ThreadError, TypeError, ValueError, SystemError):
            pass

        self._verifyThread = None
        self._verifying = False
        self._verified = False
        self.verify_button.disabled = False
        self.verify_button.text = 'Verify'

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
        self.verify_button.text = 'Verifying...'

        store = copy.deepcopy(App.get_running_app().keyStore)

        self._verifyThread = ThreadWithExc(target=self.verifyDEPTask,
                args=(self._jsonDEP, store, key,))
        self._verifyThread.start()

    @mainthread
    def verifyCb(self, result):
        if not self._verifying:
            return

        self._verifying = False
        self._verifyThread = None
        if result:
            self.verify_button.text = 'Verify'

            displayError(result)

        else:
            self._verified = True
            self.verify_button.disabled = True
            self.verify_button.text = 'Valid DEP'

    def verifyDEPTask(self, json, store, key):
        try:
            verify.verifyDEP(json, store, key)
            self.verifyCb(None)
        except (receipt.ReceiptException, verify.DEPException) as e:
            self.verifyCb(e)
        # In case one of the certs is malformed.
        except ValueError as e:
            self.verifyCb(e)
        except threading.ThreadError:
            pass

    def dismissPopup(self):
        self._popup.dismiss()

    def loadDEP(self):
        content = LoadDialog(load=self.loadDEPCb,
                cancel=self.dismissPopup)
        self._popup = getPopup("Load DEP", content)
        self._popup.open()

    def loadDEPCb(self, path, filename):
        if not filename or len(filename) < 1:
            return

        try:
            with open(os.path.join(path, filename[0])) as f:
                self._jsonDEP = json.loads(f.read())
        except (IOError, ValueError) as e:
            displayError(e)
            self.dismissPopup()
            return

        self.verifyAbort()
        if not self.updateDEPDisplay():
            self.verify_button.disabled = True
            self._jsonDEP = None

        self.dismissPopup()

    def loadAES(self):
        content = LoadDialog(load=self.loadAESCb,
                cancel=self.dismissPopup)
        self._popup = getPopup("Load AES Key", content)
        self._popup.open()

    def loadAESCb(self, path, filename):
        if not filename or len(filename) < 1:
            return

        try:
            full = os.path.join(path, filename[0])
            with open(full) as f:
                if full.endswith(".json"):
                    jsonAES = json.loads(f.read())
                    self.aesInput.text = jsonAES["base64AESKey"]
                else:
                    self.aesInput.text = f.read()
        except (IOError, ValueError) as e:
            displayError(e)
        except KeyError:
            displayError("Malformed crypto container")

        self.dismissPopup()

class KeyStoreWidget(BoxLayout):
    pubKeyGroup = ObjectProperty(None)
    certGroup = ObjectProperty(None)
    treeView = ObjectProperty(None)

    def on_treeView(self, instance, value):
        tv = self.treeView
        self.pubKeyGroup = tv.add_node(TreeViewButton(text='Public Keys',
                on_press=self.addPubKey))
        self.certGroup = tv.add_node(TreeViewButton(text='Certificates',
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
                    text=kid,
                    on_press=self.delKey,
                    key_id=kid), self.certGroup)
            else:
                tv.add_node(TreeViewKeyButton(
                    text=kid,
                    on_press=self.delKey,
                    key_id=kid), self.pubKeyGroup)

    def delKey(self, btn):
        App.get_running_app().keyStore.delKey(btn.key_id)
        self.buildKSTree()

    def dismissPopup(self):
        self._popup.dismiss()

    def addPubKey(self, btn):
        content = LoadDialog(load=self.addPubKeyCbKey, cancel=self.dismissPopup)
        self._popup = getPopup("Load PEM Public Key", content)
        self._popup.open()

    def addCert(self, btn):
        content = LoadDialog(load=self.addCertCb, cancel=self.dismissPopup)
        self._popup = getPopup("Load PEM Certificate", content)
        self._popup.open()

    def addPubKeyCbKey(self, path, filename):
        if not filename or len(filename) < 1:
            return

        try:
            with open(os.path.join(path, filename[0])) as f:
                self._tmpPubKey = f.read()
        except IOError as e:
            displayError(e)
            self.dismissPopup()
            return

        content = SingleValueDialog(receive_value=self.addPubKeyCbId,
                cancel=self.dismissPopup)

        self.dismissPopup()
        self._popup = getPopup("Enter Public Key ID", content)
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
        except (IOError, ValueError) as e:
            displayError(e)

        self.dismissPopup()
        self.buildKSTree()

    def importKeyStore(self):
        content = LoadDialog(load=self.importKeyStoreCb,
                cancel=self.dismissPopup)
        self._popup = getPopup("Load Key Store", content)
        self._popup.open()

    def exportKeyStore(self):
        content = SaveDialog(save=self.exportKeyStoreCb,
                cancel=self.dismissPopup)
        self._popup = getPopup("Save Key Store", content)
        self._popup.open()

    def importKeyStoreCb(self, path, filename):
        if not filename or len(filename) < 1:
            return

        try:
            full = os.path.join(path, filename[0])
            if full.endswith(".json"):
                with open(full) as f:
                    jsonKS = json.loads(f.read())
                    App.get_running_app().keyStore = \
                            key_store.KeyStore.readStoreFromJson(jsonKS)
            else:
                config = configparser.RawConfigParser()
                config.optionxform = str
                with open(full) as f:
                    config.readfp(f)
                App.get_running_app().keyStore = \
                        key_store.KeyStore.readStore(config)
        except (IOError, ValueError, configparser.Error) as e:
            displayError(e)
        except KeyError:
            displayError("Malformed crypto container")

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
        except IOError as e:
            displayError(e)

        self.dismissPopup()

class MainWidget(BoxLayout):
    pass

class RKToolApp(App):
    keyStore = key_store.KeyStore()
    ksWidget = None

    def on_pause(self):
        return True

    def on_resume(self):
        pass

    def updateKSWidget(self):
        if self.ksWidget:
            self.ksWidget.buildKSTree()

    def updateHeight(self, instance, value):
        for c in Window.children:
            c.height = Window.height - Window.keyboard_height

    def build(self):
        Window.bind(keyboard_height=self.updateHeight)
        return MainWidget()

if __name__ == '__main__':
    RKToolApp().run()
