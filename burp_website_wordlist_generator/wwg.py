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
        self.page_text.appent(data)
    
    