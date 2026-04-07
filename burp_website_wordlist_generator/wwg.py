from burp import IBurpExtender
from burp import IContextMenuFactory

from java.util import ArrayList
from javax.swing import JmenuItem

from datetime import datetime
from HTMLParser import HTMLParser

import re 

class TagStripper(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.page_text = []
    
    def handle_data(self, data):
        self.page_text.append(data)
    def handle_comment(self, data):
        self.page_text.append(data)
    
    def strip(self, html):
        self.feed(html)
        return "".join(self.page_text)
    
class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.context = None
        self.hosts = set()

        # Start with a common password
        self.wordlist = set(["password"])
        # Prepare our extension
        callbacks.setExtensionName("Burp WWG")
        callbacks.registerContextMenuFactory(self)

        return
    
    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()
        menu_list.add(JmenuItem("Create a wordlist", 
                                actionPerformed=self.wordlist_menu))

        return menu_list
    
    def wordlist_menu(self, event):
        # Retrieve detailes what the user clicked on
        http_traffic =  self.context.getSelectedMessages()
        for traffic in http_traffic:
            http_service = traffic.getHttpService()
            host = http_service.getHost()
            self.hosts.add(host)
            http_response = traffic.getResponse()
            if http_response:
                self.get_words(http_response)
        
        self.display_wordlist()
        return