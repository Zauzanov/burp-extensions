# burp-bing
The extension is a `legacy`(as Bing API is dead now) Burp passive recon helper that takes a selected host, queries Bing for related indexed assets, prints the findings, and adds discovered URLs into Burp scope.

It adds a `right-click menu` item called `Send to Bing`. When you click it on one or more selected Burp requests, it:
1. extracts the target host;
2. figures out whether that host is an IP address or a domain name;
3. runs Bing searches for:;
    - `ip:<ip>`;
    - and, if it’s a domain, also `domain:<host>`.
4. parses the Bing API results;
5. prints the discovered URLs/details to Burp’s output;
6. autmatically adds discovered URLs to Burp scope if they are not already in scope.

So the main func is: find other internet-exposed sites related to the selected target and bring them into Burp’s scope for further testing.