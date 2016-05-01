#!/usr/bin/python3

import kivy
kivy.require('1.9.0')

import base64 
import configparser
import copy
import json
import os
import threading
import utils

from kivy.adapters.dictadapter import DictAdapter
from kivy.app import App
from kivy.clock import mainthread
from kivy.properties import ObjectProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.listview import CompositeListItem, ListItemButton, ListItemLabel
from kivy.uix.modalview import ModalView
from kivy.uix.popup import Popup
from kivy.uix.selectableview import SelectableView
from kivy.uix.treeview import TreeView, TreeViewNode, TreeViewLabel

import algorithms
import key_store
import receipt
import verify_receipt

class ErrorDialog(FloatLayout):
    exception = ObjectProperty(None)
    cancel = ObjectProperty(None)

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
                ,13: ( 'Signature', receipt.signature )
                }
        self.adapter.data = maps

    def verify(self):
        self.verify_button.text = 'Verifying...'
        self.verify_button.disabled = True

        rec = copy.deepcopy(self._receipt)
        prefix = copy.deepcopy(self._algorithmPrefix)
        store = copy.deepcopy(App.get_running_app().keyStore)

        threading.Thread(target=self.verifyReceiptTask,
                args=(rec, prefix, store,)).start()

    @mainthread
    def verifyCb(self, result):
        if result:
            self.verify_button.text = 'Verify'
            self.verify_button.disabled = False

            content = ErrorDialog(exception=result, cancel=self.dismissPopup)
            self._popup = Popup(title="Error", content=content,
                    size_hint=(0.9, 0.9))
            self._popup.open()

        else:
            self.verify_button.text = 'Valid Signature'
            self.verify_button.disabled = True

    # TODO: manage proper termination of this thread
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
        self._popup = Popup(title="Load AES Key", content=content,
                size_hint=(0.9, 0.9))
        self._popup.open()

    def loadAESCb(self, path, filename):
        if not filename or len(filename) < 1:
            return

        key = None
        with open(os.path.join(path, filename[0])) as f:
            key = f.read()

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
                self._key = base64.b64decode(key.encode('utf-8'))
        except Exception as e:
            self.aes_input.text = ''
            content = ErrorDialog(exception=e, cancel=self.dismissPopup)
            self._popup = Popup(title="Error", content=content,
                    size_hint=(0.9, 0.9))
            self._popup.open()

        if self._key:
            self.decrypt_button.disabled = True
            self.updateView()

class VerifyReceiptWidget(BoxLayout):
    receiptInput = ObjectProperty(None)
    _input_type = 'JWS'

    def dismissPopup(self):
        self._popup.dismiss()

    def loadReceipt(self):
        content = LoadDialog(load=self.loadReceiptCb,
                cancel=self.dismissPopup)
        self._popup = Popup(title="Load Receipt", content=content,
                size_hint=(0.9, 0.9))
        self._popup.open()

    def loadReceiptCb(self, path, filename):
        if not filename or len(filename) < 1:
            return

        with open(os.path.join(path, filename[0])) as f:
            self.receiptInput.text = f.read()

        self.dismissPopup()

    def selectInputType(self, inputType):
        self._input_type = inputType

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
            else:
                return

            content = ViewReceiptWidget(rec, prefix, False, None,
                    cancel=self.dismissPopup)
            self._popup = ModalView(auto_dismiss=False)
            self._popup.add_widget(content)
            self._popup.open()
        except receipt.ReceiptException as e:
            content = ErrorDialog(exception=e, cancel=self.dismissPopup)
            self._popup = Popup(title="Error", content=content,
                    size_hint=(0.9, 0.9))
            self._popup.open()

class VerifyDEPWidget(BoxLayout):
    # TODO: actual verification of the DEP

    treeView = ObjectProperty(None)
    aesInput = ObjectProperty(None)

    def addCert(self, btn):
        App.get_running_app().keyStore.putPEMCert(utils.addPEMCertHeaders(btn.text))
        App.get_running_app().updateKSWidget()

    def viewReceipt(self, btn):
        try:
            rec, prefix = receipt.Receipt.fromJWSString(btn.text)

            # TODO: properly pass isValid and key
            content = ViewReceiptWidget(rec, prefix, False, self.aesInput.text,
                    cancel=self.dismissPopup)
            self._popup = ModalView(auto_dismiss=False)
            self._popup.add_widget(content)
            self._popup.bind(on_open=content.firstDisplay)
            self._popup.open()
        except receipt.ReceiptException as e:
            content = ErrorDialog(exception=e, cancel=self.dismissPopup)
            self._popup = Popup(title="Error", content=content,
                    size_hint=(0.9, 0.9))
            self._popup.open()

    def updateDEPDisplay(self):
        tv = self.treeView

        for n in tv.iterate_all_nodes():
            tv.remove_node(n)

        groupIdx = 1
        for group in self._jsonDEP['Belege-Gruppe']:
            groupNode = tv.add_node(TreeViewLabel(text=('Gruppe %d' % groupIdx)))
            groupIdx += 1

            certNode = tv.add_node(TreeViewLabel(text='Signaturzertifikat'),
                    groupNode)
            chainNode = tv.add_node(TreeViewLabel(text='Zertifizierungsstellen'),
                    groupNode)
            receiptsNode = tv.add_node(TreeViewLabel(text='Belege-kompakt'),
                    groupNode)

            cert = group['Signaturzertifikat']
            if cert:
                tv.add_node(TreeViewButton(text=cert, on_press=self.addCert),
                        certNode)

            for cert in group['Zertifizierungsstellen']:
                tv.add_node(TreeViewButton(text=cert, on_press=self.addCert),
                        chainNode)

            for receipt in group['Belege-kompakt']:
                tv.add_node(TreeViewButton(text=receipt,
                    on_press=self.viewReceipt), receiptsNode)

    def dismissPopup(self):
        self._popup.dismiss()

    def loadDEP(self):
        content = LoadDialog(load=self.loadDEPCb,
                cancel=self.dismissPopup)
        self._popup = Popup(title="Load DEP", content=content,
                size_hint=(0.9, 0.9))
        self._popup.open()

    def loadDEPCb(self, path, filename):
        if not filename or len(filename) < 1:
            return

        with open(os.path.join(path, filename[0])) as f:
            self._jsonDEP = json.loads(f.read())

        self.updateDEPDisplay()
        self.dismissPopup()

    def loadAES(self):
        content = LoadDialog(load=self.loadAESCb,
                cancel=self.dismissPopup)
        self._popup = Popup(title="Load AES Key", content=content,
                size_hint=(0.9, 0.9))
        self._popup.open()

    def loadAESCb(self, path, filename):
        if not filename or len(filename) < 1:
            return

        with open(os.path.join(path, filename[0])) as f:
            self.aesInput.text = f.read()

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

        iterator = iter(tv.iterate_all_nodes(node=self.pubKeyGroup))
        next(iterator)
        for n in iterator:
            tv.remove_node(n)

        iterator = iter(tv.iterate_all_nodes(node=self.certGroup))
        next(iterator)
        for n in iterator:
            tv.remove_node(n)

        ks = App.get_running_app().keyStore
        for kid in ks.getKeyIds():
            if ks.getCert(kid):
                tv.add_node(TreeViewButton(text=kid, on_press=self.delKey),
                        self.certGroup)
            else:
                tv.add_node(TreeViewButton(text=kid, on_press=self.delKey),
                        self.pubKeyGroup)

    def delKey(self, btn):
        App.get_running_app().keyStore.delKey(btn.text)
        self.buildKSTree()

    def dismissPopup(self):
        self._popup.dismiss()

    def addPubKey(self, btn):
        content = LoadDialog(load=self.addPubKeyCbKey, cancel=self.dismissPopup)
        self._popup = Popup(title="Load PEM Public Key", content=content,
                size_hint=(0.9, 0.9))
        self._popup.open()

    def addCert(self, btn):
        content = LoadDialog(load=self.addCertCb, cancel=self.dismissPopup)
        self._popup = Popup(title="Load PEM Certificate", content=content,
                size_hint=(0.9, 0.9))
        self._popup.open()

    def addPubKeyCbKey(self, path, filename):
        if not filename or len(filename) < 1:
            return

        with open(os.path.join(path, filename[0])) as f:
            self._tmpPubKey = f.read()

        content = SingleValueDialog(receive_value=self.addPubKeyCbId,
                cancel=self.dismissPopup)

        self.dismissPopup()
        self._popup = Popup(title="Enter Public Key ID", content=content,
                size_hint=(0.9, 0.9))
        self._popup.open()

    def addPubKeyCbId(self, keyId):
        App.get_running_app().keyStore.putPEMKey(keyId, self._tmpPubKey)
        self.dismissPopup()
        self.buildKSTree()

    def addCertCb(self, path, filename):
        if not filename or len(filename) < 1:
            return

        with open(os.path.join(path, filename[0])) as f:
            App.get_running_app().keyStore.putPEMCert(f.read())

        self.dismissPopup()
        self.buildKSTree()

    def importKeyStore(self):
        content = LoadDialog(load=self.importKeyStoreCb,
                cancel=self.dismissPopup)
        self._popup = Popup(title="Load Key Store", content=content,
                size_hint=(0.9, 0.9))
        self._popup.open()

    def exportKeyStore(self):
        content = SaveDialog(save=self.exportKeyStoreCb,
                cancel=self.dismissPopup)
        self._popup = Popup(title="Save Key Store", content=content,
                size_hint=(0.9, 0.9))
        self._popup.open()

    def importKeyStoreCb(self, path, filename):
        if not filename or len(filename) < 1:
            return

        config = configparser.RawConfigParser()
        config.optionxform = str
        config.read(os.path.join(path, filename[0]))
        App.get_running_app().keyStore = key_store.KeyStore.readStore(config)

        self.dismissPopup()
        self.buildKSTree()

    def exportKeyStoreCb(self, path, filename):
        if not filename:
            return

        config = configparser.RawConfigParser()
        config.optionxform = str
        App.get_running_app().keyStore.writeStore(config)
        with open(os.path.join(path, filename), 'w') as f:
            config.write(f)

        self.dismissPopup()

class MainWidget(BoxLayout):
    pass

class RKToolApp(App):
    keyStore = key_store.KeyStore()
    ksWidget = None

    def updateKSWidget(self):
        if self.ksWidget:
            self.ksWidget.buildKSTree()

    def build(self):
        return MainWidget()

if __name__ == '__main__':
    RKToolApp().run()
