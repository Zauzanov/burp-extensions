# burp-urlscan 
The extension is a Burp passive recon helper that takes a selected host, searches `urlscan.io` historical scan data for related pages and infrastructure, prints the findings, and adds discovered URLs into Burp scope for follow-up analysis.

## PREPARATIONS
## 1. Get an API key from https://urlscan.io/; 
## 2. Add it to `burp_urlscan.py`;
## 3. Download Jython standalone: 
```bash
https://www.jython.org/download 
https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.4/jython-standalone-2.7.4.jar
```

`Jython` is an implementation of the Python programming language that runs on the `Java Virtual Machine (JVM)`. It allows us to write Python code that can seamlessly interact with existing Java classes, libraries, and frameworks. Jython supports Python 2. 

### 2. Link JAR-file to Burp: 
**Tabs**:<br> 
`Burp`  — `Settings` — `Extensions` — `Core extension settings` — `Python environment` — `Location of Jython standalone JAR file`: 
<br>

![JAR-file location](Screenshots/01%20-%20JAR%20Location.png) 


### 3. Upload our custom extension(`burp_urlscan.py`) to Burp: 
`Burp` — `Extensions` — `Add` — `Extension type: Python` — `Extension file: burp_urlscan.py` — `Click Next`:
<br>

![Add Custom Extension](Screenshots/02%20-%20Add%20extension.png) 

### 4. Run DVWA using docker or use `Demo.testfire.net` — deliberately vulnerable banking web-app, designed by IBM for testing security tools like scanners: 
```bash
docker pull vulnerables/web-dvwa
docker run -d --name dvwa -p 127.0.0.1:8080:80 vulnerables/web-dvwa
```
Open:

* `http://localhost:8080`

Default login is typically:

* **admin / password**

Reset databases. 

## STEPS
### 1. Send a request in DVWA:
![Send Request](Screenshots/03%20-%20Send%20Request.png)

### 2. Intercept it using Burp Proxy+FoxyProxy, then click `Right Click` — `Extension: Send to urlscan.io`: 
![Intercept](Screenshots/04%20-%20Intercept.png)

### 3. Check the `urlscan` search results:
![Results](Screenshots/05%20-%20Results.png)

### 4. Detected hosts automatically added to the Burp Target area:
![Results](Screenshots/06%20-%20Target%20scope.png)

IT WORKS! 

---

### 5. ⚠️ If you get the following error when uploading the extension to Burp:

```java
SyntaxError: Non-ASCII character in file '/home/kali/Desktop/burp/burp_urlscan.py', but no encoding declared; see http://www.python.org/peps/pep-0263.html for details

	at org.python.core.Py.SyntaxError(Py.java:169)
	at org.python.core.ParserFacade.fixParseError(ParserFacade.java:112)
	at org.python.core.ParserFacade.parse(ParserFacade.java:197)
	at org.python.core.Py.compile_flags(Py.java:2282)
	at org.python.core.__builtin__.execfile_flags(__builtin__.java:527)
	at org.python.util.PythonInterpreter.execfile(PythonInterpreter.java:287)
	at java.base/jdk.internal.reflect.DirectMethodHandleAccessor.invoke(DirectMethodHandleAccessor.java:103)
	at java.base/java.lang.reflect.Method.invoke(Method.java:580)
	at burp.Zfh.Zs(Unknown Source)
	at burp.Zt.Zt(Unknown Source)
	at burp.Zp7r.ZT(Unknown Source)
	at burp.Zh6f.lambda$load$2(Unknown Source)
	at java.base/java.util.concurrent.Executors$RunnableAdapter.call(Executors.java:572)
	at java.base/java.util.concurrent.FutureTask.run(FutureTask.java:317)
	at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1144)
	at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:642)
	at java.base/java.lang.Thread.run(Thread.java:1583)
```

It means your code comments contain a non-ASCII character, like: 
- an em dash: `—` vs. a normal ASCII hyphen `-`. This one character alone is enough to trigger the error.

#### 5.1 Fix it, adding an encoding declaration: 

Add this as the first line of the file:
```python
# -*- coding: utf-8 -*-
```
So your file should start like this:
```python
# -*- coding: utf-8 -*-

# Burp Extender API interfaces
from burp import IBurpExtender
from burp import IContextMenuFactory
``` 
It tells Jython that this file is encoded as UTF-8, so Unicode characters in comments are allowed.