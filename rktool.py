#!/usr/bin/python3

import kivy
kivy.require('1.9.0')

from kivy.uix.boxlayout import BoxLayout
from kivy.app import App

class MainWidget(BoxLayout):
    pass

class RKToolApp(App):
    def build(self):
        return MainWidget()

if __name__ == '__main__':
    RKToolApp().run()
