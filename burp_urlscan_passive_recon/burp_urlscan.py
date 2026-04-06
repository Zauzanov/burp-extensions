# Burp Extender API interfaces
from burp import IBurpExtender                                              # Neccessary for creating custom extensions, w/o it Burp wouldnt know to load our extension.
from burp import IContextMenuFactory                                        # Creates right-click context menu items.

from java.net import URL                                                    # Converts a string with URL into Java objects that Burp can understand.
from java.util import ArrayList                                             # Burp expects Java collections in many places, so this returns the context menu items in a Java-friendly format.
from javax.swing import JMenuItem                                           # Creates the actual right-click menu entry shown in Burp.
from thread import start_new_thread                                         # Imports Python 2/Jython low-level threading function in order to run searches in the background. 
                                                                            # So Burp UI does not freeze while waiting for the urlscan.io API response.

import json                                                                 # For parsing the API response body.
import socket                                                               # For checking wether a host is an IP and resolving a domain to an IP.
import urllib                                                               # Used for URL-encoding the query string. Ensures special characters in the search query do not break the GET request. 
                                                                            # In URLs, characters like these are special: ? & = # % : /. So if we inject them directly into the URL, the server may interpret them as URL syntax instead of data.

API_KEY = "YOUR_URLSCAN_API_KEY"                                            # Replace it with your own key.
API_HOST = "urlscan.io"                                                     # Remote API server.
SEARCH_PATH = "/api/v1/search/"                                             # The search API from docs: https://docs.urlscan.io/apis/urlscan-openapi/search .                                                                         
                                                                            # Allows users to search for historically website scans, hostnames, domains, TLS certificates and incidents.

SEARCH_SIZE = 25                                                            # The max number of search results requested from urlscan.io. 



# Burp extension class, as Burp looks for a class named BurpExtender 
# implementing IBurpExtender. This Class also implements
# IContextMenuFactory, so it can create right-click menu items. 
class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks                                         # Lets other method access Burp functions.
        self._helpers = callbacks.getHelpers()                              # Burp helpers can do: analyze req/resps; build reqs; decode/encode data.
        self.context = None                                                 # Creates an instance variable to store the current right-click context. 

        callbacks.setExtensionName("Send to urlscan.io")                    # Sets the extension name as shown in Burp's Extensions tab.                   
        callbacks.registerContextMenuFactory(self)                          # Registers this class as a provider of context menu items.
        print("urlscan.io extension loaded")
        return

    # Creating the right-click menu item
    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()                                             # Create a Java ArrayList to hold menu items.
        menu_list.add(JMenuItem("Send to urlscan.io", 
                                actionPerformed=self.urlscan_menu))         # Creates a menu item labeled 'Send to...'.
        return menu_list                                                    # Returns the list of menu items to Burp. That's how the custom menu entry appears.

    # Menu click handler.
    # This method runs when the user clicks our custom menu item.
    def urlscan_menu(self, event):
        http_traffic = self.context.getSelectedMessages()                   # Asks the stored Burp context for the selected HTTP messages. This returns the selected reqs/resps the user highlighted in Burp.

        if not http_traffic:
            print("No requests highlighted")
            return

        print("%d requests highlighted" % len(http_traffic))

        # Loops throuh each selected HTTP message
        for traffic in http_traffic:
            http_service = traffic.getHttpService()                         # Gets the associated HTTP service for that message. This gives access to: host; port; protocol.
            host = http_service.getHost()                                   # Extracts the host from the selected message.
            print("User selected host: %s" % host)
            self.urlscan_search(host)                                       # Passes the host into the main search-preparation function. 

        return

    # Host processing and deciding what to search:
    # this method decides how to search urlcan
    # based no whether the host is IP or domain name.
    def urlscan_search(self, host):
        # Check whether host is an IP or a domain
        try:                                                                # It tries to interpret `host` as an IPv4 address.
            is_ip = bool(socket.inet_aton(host))                            # `socket.inet_aton` succeeds if `host` is a valid IPv4 address. `bool(...)` converts the result into True/False.
        except socket.error:                                                # It throws `socket.error` if not. For example: "8.8.8.8" - valid IP; "example.com" - error.
            is_ip = False
        
        if is_ip:
            ip_address = host                                               # If the selected host is already an IP, store it in here. 
            domain = False                                                  # mark `domain` as False.
        else:
            domain = True                                                   # If not an IP, assume it is a domain name.
            try:                                                            # If it's a domain: try DNS resolution using `socket.gethostbyname`.
                ip_address = socket.gethostbyname(host)                     # If resoluiton succeeds, store its IPv4 address.
            except socket.error as err:
                ip_address = None                                           # If resolution fails, set this, as our extension wants to search urlscan both by resolved IP and domain name.
                print("Could not resolve %s: %s" % (host, err))

        # Search by IP when possible
        if ip_address:
            start_new_thread(self.urlscan_query, 
                             ("page.ip:%s" % ip_address,))                  # Starts a new background thread that searches urlscan. 

        # Search by domain
        if domain:
            start_new_thread(self.urlscan_query, 
                             ("page.domain:%s" % host,))                    # Searches urlscan results where the scanned page domain matches the host. 

            # Optional extra search for the apex/domain as submitted task.
            # This starts a 3rd possible search for the host inside 
            # the original submitted task URL.
            start_new_thread(self.urlscan_query, 
                             ("task.url:*%s*" % self._escape_query_value(host),)) # Query example: task.url:*example.com*, which means: it looks for scans where the task URL contains the host anywhere.
                                                                                  # Match anything before example.com and anything after it too.
                                                                                  # Bc someties the exact page.domain may differ, but the submitted URL still contains the target domain.
                                                                                  # It helps to find subdomains, redirects and so on. 
        return

    # Escaping query syntax
    def _escape_query_value(self, value):
        # Minimal escaping for Elasticsearch query-string special chars
        special = ['\\', '+', '-', '=', '&', '|', '>', '<', '!', '(', ')',
                   '{', '}', '[', ']', '^', '"', '~', '*', '?', ':', '/']
        escaped = value                                                             # Starts with the original string, then modifies that copy step by step. 
        for ch in special:                                                          # Loops over all special characters and prepends a backslash to each. 
            escaped = escaped.replace(ch, '\\' + ch)                                # example.com/path?x=1 becomes: example.com\/path\?x=1
                                                                                    # Without escaping, crafted or odd host values could: break the query; change search meaning; produce unexpected results. 
        return escaped

    # Makes the API request(urlscan query) and processes the results.
    # It runs in background threads. 
    def urlscan_query(self, query_string):
        print("Performing urlscan search: %s" % query_string)                       # Logs the query being sent.

        # Builds the URL query string.
        # (the part after the ? in the URL: 
        # GET /api/v1/search/?q=page.domain%3Aexample.com&size=25 HTTP/1.1) 
        # Example: q=page.ip%3A8.8.8.8&size=25.
        params = "q=%s&size=%d" % (urllib.quote(query_string), 
                                   SEARCH_SIZE)                                     # URL-encodes reserved characters so they can safely appear inside the HTTP GET query.

        
        # Building the raw HTTP request.
        http_request = "GET %s?%s HTTP/1.1\r\n" % (SEARCH_PATH, 
                                                   params)                          # Builds the request line: GET /api....HTTP/1.1 . 
        http_request += "Host: %s\r\n" % API_HOST                                   # Adds the Host header. Required for HTTP/1.1.
        http_request += "Connection: close\r\n"                                     # Tells the server to close the connection after the response. 
        http_request += "api-key: %s\r\n" % API_KEY                                 # Adds the API key header for auth. 
                                                                                    # UNSAFE FOR PRODUCTION! — direcrtly injects our API key into the raw HTTP request, 
                                                                                    # as in this case the key is hardcoded.
        http_request += "Accept: application/json\r\n"                              # Tells the server we want JSON back. 
        http_request += "User-Agent: Burp Suite urlscan.io extension\r\n\r\n"       # Adds a UA header and terminates the headers with an empty line. 

        # Sends the request through Burp's API
        response_bytes = self._callbacks.makeHttpRequest(API_HOST, 
                                                         443, True, http_request)   # Opens a TLS(True stands for) connections to urlscan.io:443, 
                                                                                    # sends the request, returns the raw response bytes. 
        response_text = response_bytes.tostring()                                   # Converts the returned byte array into a string. 


        # Separating headers from body: 
        try:
            json_body = response_text.split("\r\n\r\n", 1)[1]
        except IndexError:
            print("Invalid HTTP response from urlscan.io")
            return

        try:
            response = json.loads(json_body)
        except (TypeError, ValueError) as err:
            print("Failed to parse urlscan.io response: %s" % err)
            print("Raw body was: %s" % json_body[:500])
            return

        results = response.get("results", [])

        if not results:
            print("No results from urlscan.io for query: %s" % query_string)
            return

        print("urlscan.io returned %d results for %s" % (len(results), query_string))

        for result in results:
            task = result.get("task", {})
            page = result.get("page", {})

            site_url = (
                page.get("url") or
                task.get("url") or
                result.get("result") or
                result.get("page", {}).get("url")
            )

            site_name = (
                page.get("title") or
                page.get("domain") or
                task.get("url") or
                "Untitled"
            )

            site_domain = page.get("domain", "N/A")
            site_ip = page.get("ip", "N/A")
            site_country = page.get("country", "N/A")
            scan_time = task.get("time", "N/A")
            result_api = result.get("result", "N/A")

            print("*" * 100)
            print("Title: %s" % site_name)
            print("URL: %s" % site_url)
            print("Domain: %s" % site_domain)
            print("IP: %s" % site_ip)
            print("Country: %s" % site_country)
            print("Scan time: %s" % scan_time)
            print("Result API: %s" % result_api)
            print("*" * 100)

            if not site_url:
                continue

            try:
                java_url = URL(site_url)
            except:
                print("Skipping invalid URL: %s" % site_url)
                continue

            if not self._callbacks.isInScope(java_url):
                print("Adding %s to Burp scope" % site_url)
                self._callbacks.includeInScope(java_url)
            else:
                print("%s already in Burp scope" % site_url)