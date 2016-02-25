import kivy
kivy.require('1.9.0')

from kivy.uix.tabbedpanel import TabbedPanel
from kivy.app import App

class MainWidget(TabbedPanel):
    pass

class RKToolApp(App):
    def build(self):
        return MainWidget()

if __name__ == '__main__':
    RKToolApp().run()
