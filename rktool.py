#!/usr/bin/python3

import kivy
kivy.require('1.9.0')

from kivy.app import App
from kivy.properties import ObjectProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.popup import Popup
from kivy.uix.treeview import TreeView, TreeViewNode

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

import configparser
import key_store
import os 

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
        config = configparser.RawConfigParser()
        config.optionxform = str
        config.read(os.path.join(path, filename[0]))
        App.get_running_app().keyStore = key_store.KeyStore.readStore(config)

        self.dismissPopup()
        self.buildKSTree()

    def exportKeyStoreCb(self, path, filename):
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

    def build(self):
        return MainWidget()

if __name__ == '__main__':
    RKToolApp().run()
