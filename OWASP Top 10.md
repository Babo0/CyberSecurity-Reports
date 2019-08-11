# OWASP Top 10
## Vulnerabilities
### A1:2017 - Injections
#### Definition / Description
TODO: Use the OWASP document to explain
 - The source, severity, and scope of injection attacks
 
	Many of the injection flaws that are available for attackers include the following: SQL, NoSQL, OS, and LDAP. The methodology of these attacks rely on injecting data and or commands in the form of requests. What makes these kinds of methods very dangerous is that almost anything that takes some kind of input could possibly lead to an area of exploitation. A contributing factor as to why this method of attack is successful is due to the lack of filters and sanitization on user input that could leave room for an attacker to find a way to exploit that flaw.

 - What kind of activity it can be used for (data exfiltration, backdooring, etc.)
 	
 	Even though using injection as a form of attack could be a tedious process due to trying to figure out the correct method, it pays off for attackers. A lot of the time these attacks are used to steal information from the Host. These could range from user accounts and passwords to gain access to sensitive files and data to also giving the attacker a reverse shell onto the server allow them to potentially gain access and escalate privileges.

#### How it Works
Explain how attackers build and deliver injection payloads. 

	When an attacker begins to test how to properly attack a host, they most likely will begin a lot of trial and error. One thing that the attack needs to know is what kind of injection language to use and how the website is set up. After fine tunning some of the info trying multiple types of attacks is needed to figure out which methods and combinations would be most effective to break out of the text to inject code. A lot of the time using Burp Suite is going to be your best bet, due to the many tools that allow you to view and follow and test a wide arrange of methods to attack certain things.

#### Scenario
Explain the UNION injection in the following URL: <http://ptl-f99df351-3bdd4c8f.libcurl.so/cat.php?id=1%20UNION%20SELECT%201,concat(login,%27:%27,password),3,4%20FROM%20users>


	Union in this URL is used to access more than one table located on the server to be able to access more than one set of info. In this example the two tables that are being called are login and password.

---
### A2:2017 - Broken Authentication
#### Definition / Description
Use the OWASP document to explain
 - The source, severity, and scope of broken authentication vulnerabilities:
 
	With the use of credentials to log into almost many services there comes a large list of security weaknesses. An attack in today's world has the ability to gain access to an endless list of credentials that can be used as in input vector to gain access to applications. By using tools that can automate the injection it makes it very easy to test large sets of data and have the potential to gain access to at least one sensitive account. If unexpired session tokens are still being used to log in, this makes almost any application potentially vulnerable.
 - What kind of damage can be done (e.g., data stealing, account tampering, etc.):
 
	The kind of damage that can be done from these attacks becomes almost endless. Gaining access to an administrator account can open the doors to a lot of data that can be stolen. A few major are the leaking of sensitive user data that is stored that can lead to social security fraud as well as identity theft. Another vector that can be extorted is money laundering or blackmail so that certain information is not released somewhere.
### How it Works
Explain why the **Brute Force** section in DVWA qualifies as a Broken Authentication vulnerability.

	When a user gets into a system the system authenticates the credentials that are put in and makes sure that they are valid. If the authentication process has any vulnerabilities like being susceptible to a dictionary attack, this means that it is a vulnerability. WIth DVWA you have the ability to use tools inside BurpSuite to stuff a large amount of usernames and passwords to try and login and that would count as a brute force attack.

### Scenario
Use Burp Intruder to solve the **Brute Force** exercise on DVWA. You'll need to:
- Intercept a request to the login form
- Set positions around the username and password
- Provide a list of usernames and passwords to test
- Use Intruder to brute-force the login form
---
##### Raw Request 
```
# Raw HTTP Request Here
```
GET /login.php HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:67.0) Gecko/20100101 Firefox/67.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=ogk698719nussk5vheqdnj7090; security=low
Upgrade-Insecure-Requests: 1

##### Intruder Request 
```
# HTTP Request w/ Intruder Positions Here
```
POST /login.php HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:67.0) Gecko/20100101 Firefox/67.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 81
Connection: close
Referer: http://localhost/login.php
Cookie: PHPSESSID=ogk698719nussk5vheqdnj7090; security=low
Upgrade-Insecure-Requests: 1

username=§bob§&password=§lol§&Login=Login&user_token=e9cc4782ef872491dad574bdc737d247
##### Valid Response(s)
```
# HTTP Response w/ Valid Credentials Here
```
POST /login.php HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:67.0) Gecko/20100101 Firefox/67.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 88
Connection: close
Referer: http://localhost/login.php
Cookie: PHPSESSID=ogk698719nussk5vheqdnj7090; security=low
Upgrade-Insecure-Requests: 1

username=admin&password=password&Login=Login&user_token=e9cc4782ef872491dad574bdc737d247

##### Mitigation
Explain two strategies for preventing this kind of attack:

	One step to mitigate this kind of attack would make parameters around usernames and passwords for accounts. By making passwords longer and adding other characters to it, it will make using password lists harder due to not being able to guess the password off the bat as well as increasing the bit size. With the larger bit size of the password, if the hashed password string were to be intercepted it would increase the time to decode it a lot longer the larger it is. 

	There are many other ways to defend against a "brute force" attack on a login form but a few other good ways to mitigate this potential is to use the lockout functionality as well as delay requests. With the lockout functionality, the account would be temporarily disabled and would require the owner of the account to access it to reactivate it. The delay of requests method would limit the amount of times a user could attempt to login to the account and then set a time delay before the user could try again. Making the process of trying to log on take a lot longer. 

---
### A6:2017 - Security Misconfiguration
#### Definition / Description
Use the OWASP document to explain:
 
 	Security misconfiguration vulnerabilities could occur when a setting or a component of an application was not properly configured or secured. A lot of these issues from insecure default configurations as well as poorly documented configurations to see where there might be an issue. Some of the areas that allow would qualify for being misconfigured would be areas such as not setting proper security headers on a web server or not disabling default configurations or functionality on a platform that could grant administrative access to an attacker. 

 What kind of damage it can do to a business:

 	If an attacker is able to exploit this type of attacker they could potentially gain access to a whole system. Whether it be a server or a computer the outcome can be very bad. The attacker could steal information or even destroy the server that they are on and cost the company a lot of money. They could also gain access to admin accounts and settings and set up back doors for later attacks or even pretend to be an admin and depending on what kind of platform the attacker got into, the ramifications could be endless.

#### Scenario
Figure out how to turn off `allow_url_fopen` and `allow_url_include`. Include the code you'd add to `php.ini` below:

you can find the file in /etc/php/5.6/cli/php.ini

within the php.ini you make the following changes 
	allow_url_fopen = On
	allow_url_include = On
	OR
	allow_url_fopen = Off
	allow_url_include = Off

---
### A7:2017 - Cross-Site Scripting (XSS)
#### Definition / Description
Use the OWASP document to explain:
- The source, scope, and severity of XSS vulnerabilities:

	There are many different ways that XSS can become a big issue but in the large scope of attacks these are viewed as moderate. Despite XSS being found in about two-thirds of all applications the area of exploitation is very small. But one of the big issues that this can cause is stealing credentials of users as well as delivering malware to victimis computers. With XSS being a vast area of exploitation there have been many tools created that can scan a website or an application and potentially find areas of opportunity for an attacker.
	
- The three different classes of XSS vulnerabilities:

	The three different types of XSS vulnerabilities are as follows: Reflected XSS, Stored XSS, and DOM XSS.
	
- What kinds of attacks can be carried out with XSS:

	With XSS an attacker is able to inject code into a web browser and have the potential of redirecting users to a different link from within the website itself. Even though this could cause a big issue, most of the time the user would need to interact with the link directly to become susceptible. An attacker also has the ability to leave something behind on an application to be used at a later time. When there are improper sanitization rules, other users and or administrators could access a link or file left behind that might allow an attacker to gain access to information or data that could be devastating. Another issue that can arise from XSS is that an attacker can potentially inject malicious software that could be downloaded by a user as well as inject key-loggers that could steal information that could be used at a later date.
 
#### How it Works
Explain how a reflected XSS payload gets echoed from an HTTP request to an HTML document:

	When the injection payload is transferred to an HTML document it can vary as to what it looks like. If the attacker is exploiting a section with an input for a username, when the payload is injected to the website it would print out a list of usernames on the screen for the attacker. Another example would be to steal cookie sessions that could be later used by the attacker and could be alerted on the screen so that it could be used. 

EX: http://www.example.com/index.php?user=“><script>alert(document.cookie)</script> 
-which would then take the current session cookie and create an alert on the screen and show the session cookie.

#### Definition / Description
For each vulnerability, use the OWASP document to explain
- The impact and severity of this vulnerability
- Three things to check to see if your web application is open to this vulnerability
- Three ways to mitigate this vulnerability

Insecure Deserialization:
	Insecure data deserialization is a vulnerability that utilises untrusted data being sent to and from an application. This could ideally allow an attacker to implement a Dos attack or even executing code that the attacker implants. But the main types of attacks that can com from this is data tampering attacks where access control is granted and the existing data structure of the application is changed. The other one is where the attacker changes application logic or how it works and can execute code to change the behavior of how the application works or run malicious code.
		With this vulnerability, checking to see if it could become a problem if fairly easy. If an Application or an API actively serialize and deserialize information and there are not steps in place to protect that information then this can become a risk.
	Some of the ways to mitigate this kind of attack could be some of the following: 
	Implementing checks on serialized data such as adding digital signatures that would be scanned and prevent data tampering and abnormal creation of data.
	Setting up logs that would monitor all deserialization and would allow the monitor to view where and what was added in an attempt to locate what happened and stop it. To be able to make this more effective, alerting and actively flagging events in which this would happen would allow a user to stop a potential attack before it had a chance to take effect like on a server.
	Another way to help mitigate against this would be to put deserialization events in a low privilege environment so that in the event that a malicious code or change of some kind were to be implemented it would not have the correct permissions to properly execute.

Sensitive Data Exposure:

	Sensitive data exposure is when data and or traffic going inbetween a user and an application is not secure. Some cases of this would be user's credit card information, health records, usernames and passowrds as well as personal information. The impact from an attacker being able to intercept this kind of information could be devistating. A lot of information could be taken and sold for a monitary value or even allow the attacker to pretend to be someone else. When an application send and or recieves information, if the data that is being sent over the internet is not encrypted it will allow it to be viewed in plain text. But when encrypting information, the host needs to make sure that the encryption method is not out of date or the default method of doing so. When old methods of encrypting data is used the way to decrypt it could be very easy for the attacker. Also something that needs to be checked would be if there are configurations missing that would make sure that secure connections are being made or data that is sent has to be encrypted.
	
	To make sure thst this type of vulnerability does not become an issue, identify what information might be sensitve and set up policies to make sure that it is encrypted and sent securly from place to place. Some other ways would also be to make sure that data that contains sensitive material is not stored for longer than it is needed and goes back to being encrypted as well as making sure that the encryption methods are strong and are used correcly. Lastly, test out the settings in place and verify that the settings that were implemented are working.
