from burp import IBurpExtender
from burp import IContextMenuFactory

from java.net import URL
from java.util import ArrayList
from javax.swing import JMenuItem
from thread import start_new_thread

import json
import socket 
import urllib
API_KEY = "YOUR_KEY"
API_HOST = "api.cognitive.microsoft.com"

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.context = None

        # Preparing our extension
        callbacks.setExtensionName("Dead-Bing")
        callbacks.registerContextMenuFactory(self)

        return

