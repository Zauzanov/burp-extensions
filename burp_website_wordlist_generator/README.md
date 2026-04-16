# burp-website-wordlist-generator
This extension is a Burp website wordlist generator — it generates a wordlist based on a website's text content to create a targeted dictionary for pentesting.

# PREPARATIONS
## 1. Download Jython standalone: 
```bash
https://www.jython.org/download 
https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.4/jython-standalone-2.7.4.jar
```

`Jython` is an implementation of the Python programming language that runs on the `Java Virtual Machine (JVM)`. It allows us to write Python code that can seamlessly interact with existing Java classes, libraries, and frameworks. Jython supports Python 2. 

## 2. Link JAR-file to Burp: 
**Tabs**:<br> 
`Burp`  — `Settings` — `Extensions` — `Core extension settings` — `Python environment` — `Location of Jython standalone JAR file`: 
<br>

![JAR-file location](docs/images/01%20-%20JAR%20Location.png) 


## 3. Upload our custom extension(`wwg.py`) to Burp: 
`Burp` — `Extensions` — `Add` — `Extension type: Python` — `Extension file: wwg.py` — `Click Next`:
<br>

![Add Custom Extension](docs/images/02%20-%20Upload.png) 

## 4. We are going to use `Demo.testfire.net` — deliberately vulnerable banking web-app, designed by IBM for testing security tools like scanners.

# STEPS
## 1. `Dashboard` — click `New live task` and choose `Add all links observed...` and click `Save`:
![Add New task](docs/images/03%20-%20new%20task.png) 

It will add all links found in the traffic.

## 2. No need to turn on Burp UI Interception. It is gonna work using FoxyProxy(as our browser still sends traffic to Burp, going through Burp's proxy listener. `Intercept on` allows us to pause the traffic for manual review):
![No Proxy](docs/images/04%20-%20no%20proxy.png)

## 3. Start scanning, browsing `Demo.testfire.net`: 
![Click](docs/images/05%20-%20click.png)

## 4. Burp scans all the links on the website. Go to `Target` Tab, select all the requests and create a wordlist:
![Create](docs/images/06%20-%20Create.png)

## 5. Let's check the result, going to `Extension` — `Output`: 
![Output](docs/images/07%20-%20Output.png)

This result can be passed to Burp Intruder, or you can save this wordlist as a file and check it like this:
```bash
cat res.txt | head -10
```
OUTPUT:
```bash
#!comment: Burp Wordlist for site(s) demo.testfire.net
about
about1
about!
about2026
About
About1
About!
About2026
account
```

# ⚠️ ERRORS ⚠️
## If you're having trouble with interception, check proxy settings:
![Proxy](docs/images/08%20-%20Proxy.png)
![Foxy1](docs/images/09%20-%20foxy1.png)
![Foxy2](docs/images/010%20-%20foxy2.png)