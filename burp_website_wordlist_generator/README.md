# burp-website-wordlist-generator
This extension is a Burp website wordlist generator — it generates a wordlist based on a website's text content to create a targeted dictionary for pentesting.

## PREPARATIONS
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

![JAR-file location](docs/images/01%20-%20JAR%20Location.png) 


### 3. Upload our custom extension(`wwg.py`) to Burp: 
`Burp` — `Extensions` — `Add` — `Extension type: Python` — `Extension file: wwg.py` — `Click Next`:
<br>

![Add Custom Extension](docs/images/02%20-%20Upload.png) 

### 4. We are going to use `Demo.testfire.net` — deliberately vulnerable banking web-app, designed by IBM for testing security tools like scanners.

## STEPS
### 1. 