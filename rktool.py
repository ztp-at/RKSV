import kivy
kivy.require('1.9.0')

from kivy.uix.label import Label
from kivy.uix.gridlayout import GridLayout
from kivy.app import App

class ReceiptVerifyWidget(GridLayout):
    pass

class RKToolApp(App):
    def build(self):
        return ReceiptVerifyWidget()

if __name__ == '__main__':
    RKToolApp().run()
