# burp-fuzzer

## PREPARATIONS
### 1. Download Jython standalone: 
```bash
https://www.jython.org/download 
https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.4/jython-standalone-2.7.4.jar
```

### 2. Link JAR-file to Burp: 
**Tabs**:<br> 
`Burp`  — `Settings` — `Extensions` — `Core extension settings` — `Python environment` — `Location of Jython standalone JAR file`: 
<br>

![JAR-file location](Screenshots/01%20-%20JAR%20Location.png) 


### 3. Upload our custom extension(`burp_fuzzer.py`) to Burp: 
`Burp` — `Extensions` — `Add` — `Extension type: Python` — `Extension file: burp_fuzzer.py` — `Click Next`:
<br>

![Add Custom Extension](Screenshots/02%20-%20Add%20extension.png) 

### 4. Run DVWA using docker: 
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

### 2. Intercept it using Burp Proxy+FoxyProxy, then send it to Burp Intruder: 
IMG 04 - Intercept
![Intercept](Screenshots/04%20-%20Intercept.png)

### 3. Set the settings like the following, adding positions and choosing `Payload type: Extension-generated` and selecting `BOOM Payload Generator` (`burp_fuzzer.py`) as a generator:
![Intruder Settings](Screenshots/05%20-%20Intruder%20settings.png)

### 4. Now we can see the result:
![Result](Screenshots/06%20-%20Result.png)

We see that our payload has broken the SQL statement. It works!

## EXPLANATION

### 1. The server's response is:
```html
<pre>You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near 'BooM!BOOM!BAM!');</script>
```

### 2. It means:
- Intruder sent our generated payload;
- The payload reached the DVWA SQL query;
- The application tried to execute it;
- MariaDB threw a syntax error because the injected quote sequence broke the SQL statement.

So the important part is not the exact error text — it iss that the response changed in a way that shows our payload is actually being inserted into the SQL context! 

### 3. If we got: ```You have an error in your SQL syntax...``` that usually means our payload added one or more ' characters and successfully altered the query structure. 

That means:
- Our custom Burp extension is generating payloads;
- Intruder is using them correctly;
- DVWA is receiving them;
- the parameter is likely injectable.

Conclusion: the script works!.

### 4. The only nuance is this:
- it proves your payload generator and Intruder workflow work;
- it does not automatically mean every payload is useful;
- it does suggest the target parameter is behaving like a SQL injection point.

### 5. `"200 Status Codes Only"` issue: 
Having 200 Status codes is ok. It means the server  successfully returned a page. It does not mean our payload failed. 

In DVWA, it’s very common for:
- the normal page to return 200
- the SQL error page to also return 200
- a successful boolean or union-based payload to also return 200

That happens because the application is still serving an HTML page successfully, only the content changes. 

OWASP’s SQL injection testing guidance also centers on how input changes query behavior, not on getting a different HTTP status code.

**Compare the response bodies and lengths, not just status code.** 