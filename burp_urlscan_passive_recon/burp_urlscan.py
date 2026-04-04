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
        menu_list.add(JMenuItem("Send to urlscan.io", actionPerformed=self.urlscan_menu)) # Creates a menu item labeled 'Send to...'.
        return menu_list                                                    # Returns the list of menu items to Burp. That's how the custom menu entry appears.

    # Menu click handler.
    # This method runs when the user clicks our custom menu item.
    def urlscan_menu(self, event):
        http_traffic = self.context.getSelectedMessages()

        if not http_traffic:
            print("No requests highlighted")
            return

        print("%d requests highlighted" % len(http_traffic))

        for traffic in http_traffic:
            http_service = traffic.getHttpService()
            host = http_service.getHost()
            print("User selected host: %s" % host)
            self.urlscan_search(host)

        return

    def urlscan_search(self, host):
        # Check whether host is an IP or a domain
        try:
            is_ip = bool(socket.inet_aton(host))
        except socket.error:
            is_ip = False

        if is_ip:
            ip_address = host
            domain = False
        else:
            domain = True
            try:
                ip_address = socket.gethostbyname(host)
            except socket.error as err:
                ip_address = None
                print("Could not resolve %s: %s" % (host, err))

        # Search by IP when possible
        if ip_address:
            start_new_thread(self.urlscan_query, ("page.ip:%s" % ip_address,))

        # Search by domain
        if domain:
            start_new_thread(self.urlscan_query, ("page.domain:%s" % host,))

            # Optional extra search for the apex/domain as submitted task
            start_new_thread(self.urlscan_query, ("task.url:*%s*" % self._escape_query_value(host),))

        return

    def _escape_query_value(self, value):
        # Minimal escaping for Elasticsearch query-string special chars
        special = ['\\', '+', '-', '=', '&', '|', '>', '<', '!', '(', ')',
                   '{', '}', '[', ']', '^', '"', '~', '*', '?', ':', '/']
        escaped = value
        for ch in special:
            escaped = escaped.replace(ch, '\\' + ch)
        return escaped

    def urlscan_query(self, query_string):
        print("Performing urlscan search: %s" % query_string)

        params = "q=%s&size=%d" % (urllib.quote(query_string), SEARCH_SIZE)

        http_request = "GET %s?%s HTTP/1.1\r\n" % (SEARCH_PATH, params)
        http_request += "Host: %s\r\n" % API_HOST
        http_request += "Connection: close\r\n"
        http_request += "api-key: %s\r\n" % API_KEY
        http_request += "Accept: application/json\r\n"
        http_request += "User-Agent: Burp Suite urlscan.io extension\r\n\r\n"

        response_bytes = self._callbacks.makeHttpRequest(API_HOST, 443, True, http_request)
        response_text = response_bytes.tostring()

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