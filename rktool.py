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

class KeyStoreGroup(Button, TreeViewNode):
    pass

import configparser
import key_store
import os 

class KeyStoreWidget(BoxLayout):
    pubKeyGroup = ObjectProperty(None)
    certGroup = ObjectProperty(None)
    keyStore = ObjectProperty(None)
    treeView = ObjectProperty(None)

    def __init__(self, **kwargs):
        super(KeyStoreWidget, self).__init__(**kwargs)
        self.keyStore = key_store.KeyStore()

    def on_treeView(self, instance, value):
        tv = self.treeView
        self.pubKeyGroup = tv.add_node(KeyStoreGroup(text='Public Keys',
                on_press=self.addPubKey))
        self.certGroup = tv.add_node(KeyStoreGroup(text='Certificates',
                on_press=self.addCert))

    def on_keyStore(self, instance, value):
        self.buildKSTree()

    def buildKSTree(self):
        if not self.keyStore or not self.treeView:
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

        ks = self.keyStore
        for kid in ks.getKeyIds():
            if ks.getCert(kid):
                tv.add_node(KeyStoreGroup(text=kid, on_press=self.viewKey),
                        self.certGroup)
            else:
                tv.add_node(KeyStoreGroup(text=kid, on_press=self.viewKey),
                        self.pubKeyGroup)

    def viewKey(self, btn):
        print("viewing key " + btn.text)

    def addPubKey(self, btn):
        print("adding pubkey")

    def addCert(self, btn):
        content = LoadDialog(load=self.addCertCb, cancel=self.dismissPopup)
        self._popup = Popup(title="Load PEM Certificate", content=content,
                size_hint=(0.9, 0.9))
        self._popup.open()

    def dismissPopup(self):
        self._popup.dismiss()

    def addCertCb(self, path, filename):
        with open(os.path.join(path, filename[0])) as f:
            self.keyStore.putPEMCert(f.read())

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
        self.keyStore = key_store.KeyStore.readStore(config)

        self.dismissPopup()

    def exportKeyStoreCb(self, path, filename):
        config = configparser.RawConfigParser()
        config.optionxform = str
        self.keyStore.writeStore(config)
        with open(os.path.join(path, filename), 'w') as f:
            config.write(f)

        self.dismissPopup()

class MainWidget(BoxLayout):
    pass

class RKToolApp(App):
    def build(self):
        return MainWidget()

if __name__ == '__main__':
    RKToolApp().run()
