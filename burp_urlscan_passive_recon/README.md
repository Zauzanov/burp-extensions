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