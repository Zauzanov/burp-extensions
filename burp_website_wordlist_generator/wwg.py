# Burp Extender API interfaces
from burp import IBurpExtender                                                                              # The main interface Burp expects for an extension.
from burp import IContextMenuFactory                                                                        # Lets the extension add items to Burp's right-click menu.

# Java classes
from java.util import ArrayList                                                                             # Burp expects Java-side objects. So we use Java's resizable list type. 
from javax.swing import JMenuItem                                                                           # Swing GUI component for a menu entry. 

# Python libs & classes
from datetime import datetime                                                                               # To append the current year to password variants. 
from HTMLParser import HTMLParser                                                                           # Python 2 HTML parses class. 

import re                                                                                                   # Python's regular expression module for word extraction. 


# The class inherits from HTMLParser to override its methods. 
# To collect text and ignore markup.  
class TagStripper(HTMLParser):
    '''
    Constructor: runs automatically when we create 
    a new object(tag_stripper = TagStripper()) from the class, 
    setting up the object's starting state.
    '''
    def __init__(self):                                                                                     
        HTMLParser.__init__(self)                                                                           # Inits the internal parser state. 
        self.page_text = []                                                                                 # A list to accumulate extracted text pieces.
    
    # Overrides HTMLParser's the same name method
    # to get the text stored after parsing
    def handle_data(self, data):
        self.page_text.append(data)
    def handle_comment(self, data):                                                                         #  To add the words stored in developer comments to the password list.
        self.page_text.append(data)
    
    def strip(self, html):
        self.feed(html)                                                                                     # Parses the HTML string and triggers callbacks(handle_data/comment) which fill self.page_text.
        return " ".join(self.page_text)                                                                     # Joins all collected chunks into 1 big string. 
    

# Implements 2 interfaces - for registration and to add rclick menu.
class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks                                                                         # Burp passes an object containing API methods for interacting with Burp.
        self._helpers = callbacks.getHelpers()                                                              # Provides utilities for parsing reqs/resps and so on. 
        self.context = None                                                                                 # To hold the context menu invocation object.
        self.hosts = set()                                                                                  # Creates an empty set to track unique hosts(no repeated hostnames) from the selected HTTP messages.

        # Start with a common password
        self.wordlist = set(["password"])
        # Prepare our extension 
        callbacks.setExtensionName("Burp WWG")                                                              # This label appears in Burp's UI.
        callbacks.registerContextMenuFactory(self)                                                          # Registers this object as the context menu factory — this tells Burp when context menu are being built.

        return
    
    # Context menu creation. 
    def createMenuItems(self, context_menu):                                                                # This context object telling us what was clicked, what messages are selected.
        self.context = context_menu                                                                         # Store the context so other methods can use it.
        # To hold menu items
        menu_list = ArrayList() 
        # Creates a GUI menu items and adds it to the list
        menu_list.add(JMenuItem("Create a wordlist", 
                                actionPerformed=self.wordlist_menu))

        return menu_list                                                                                    # Returns Java list of menu items to Burp. Burp adds them to the UI.
    
    # Menu click handler
    def wordlist_menu(self, event):
        # Retrieve details what the user clicked on
        http_traffic =  self.context.getSelectedMessages()
        # Each `traffic` item represents 1 selected HTTP message
        for traffic in http_traffic:
            http_service = traffic.getHttpService()                                                         # Gets connection details: host, port, protocol.
            host = http_service.getHost()                                                                   # Extracts the hostname from the HTTP service.
            self.hosts.add(host)                                                                            # Adds the host to the set of hosts. 
            http_response = traffic.getResponse()                                                           # Gets the raw HTTP response bytes associated with the selected message.
            # Checks that a response exists, 
            # then calls the word extraction method.
            if http_response:
                self.get_words(http_response)
        
        self.display_wordlist()                                                                             # After all selected responses are processed, prints the final wordlist. 
        return
    
    # Response parsing & word extraction
    def get_words(self, http_response):                                                                     # Takes 1 HTTP response and extracts candidate words.
        '''
        Converts the response byte array into a string.

        Splits the raw HTTP response into headers and body. 
        1 means split only once. 
        '''
        headers, body = http_response.tostring().split('\r\n\r\n', 1) 

        # Skip non-textual responses:
        # if this text doesn't exist anywhere in the headers, 
        # stop processing this response — leave the func immediately.
        if headers.lower().find("content-type: text") == -1: 
            return
        
        # Create a new instance of our custom HTML parser class.
        # Fresh instance - fresh page_text list. 
        tag_stripper = TagStripper()
        page_text = tag_stripper.strip(body)                                                                # Passing the response body there, we parse the HTML, collect data/comms, return plain text. 

        # Regular expression to extract word-like strings(3 chars minimum).
        words = re.findall("[a-zA-Z]\w{2,}", page_text) 

        # Iterates through every matched word
        for word in words:
            # filter out long strings
            if len(word) <= 12:
                self.wordlist.add(word.lower())                                                             # Converts to lowercase, before storing to the set. 
        
        return
    
    # Takes a base word and produces password variants
    def mangle(self, word):
        year = datetime.now().year                                                                          # Gets current year as an integer to make admin2026-like vars.
        suffixes = ["", "1", "!", year]                                                                     # To append to each base word.
        mangled = []                                                                                        # A list to hold generated vars. 

        # Loops through 2 base forms: 
        # original word and capitalized version. 
        for password in (word, word.capitalize()):
            for suffix in suffixes:                                                                         # appends every suffix to every base form.
                # Builds a new string, adding each to the list.  
                mangled.append("%s%s" % (password, suffix))
        return mangled                                                                                      # Returns the list of generated password candidates.
    
    # Prints final results. 
    def display_wordlist(self):
        print("#!comment: Burp Wordlist for site(s) %s" % ", ".join(self.hosts))
        # Generates vars for each base word,
        # prints each variant. 
        for word in sorted(self.wordlist):
            for password in self.mangle(word):
                print password
        
        return
    
