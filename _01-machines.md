# Relativity

Keys : ProFTPD 1.2.8 - 1.2.9 mod_sql, php wrappers data://text/plain;base64, UnrealIRCd, sudo -l

- Exploit ProFTPD mod_sql ==> Discovery web directory
- Exploit php wrapper data://text/plain ==> copy isa private key
- Connect to ssh server ==> Discovery UnrealIRCd. This version containt a backdoor
- Exploit UnrealIRCd server ==> Gain access's another user
- Modify script execute with root privilege to gain root shell


# Pipe

Keys : method http, .htaccess <Limit></Limit>, php serialization, php destructor, exploiting wildcard, tar Wildcard Injection


- Scan web service ==> found web hidden directory
- Test different http method ==> found web hidden directory
- Read souce code in a .bak file
- Exploit php destructor to gain reverse shell
- Discovery crontab execute by root user to backup the data with tar command
- Exploit tar wildcard to get root


# Sleepy

Keys : Java Debug Wire Protocol (JDWP) version 1.6 1.7.0_71, tomcat, Apache Tomcat Proxy, shellshock, bash-4.2

- Exploit JDWP to copy _/etc/tomcat/tomcat-users.xml_ to _/var/ftp/pub/_
- Read tomcat-users.xml with the ftp service
- Install Apache Tomcat Proxy
- Upload shell with "Manager App"
- Upgrade shell
- Exploit shellshock to gain root shell

# K2


Keys: shared libraries, cat -v, bash -p, ruby gem which, sudo 1.8.6p7, privilege increase with SHELLOPTS and PS4

- Connect to ssh server with user/password
- Exploit shared libraries in C ==> gain user2's access
- Discovery task on crontab hidden by ^[[3A
- Modify ruby library 'gem which zip' ==> gain user3's access
- Exploit suid program by using SHELLOPTS and PS4 on bash 4.2 ==> get root bash shell



# Persistence


Keys : ping exfiltration,  escaping from limited bash (ftp, nano), escaping a chroot jail, buffer overflow, canary protection

- Scan web server ==> found debug.php
- Command injection with debug.php. Use ping exfiltration ==> found sysadmin-tool in the root web directory
- Execute sysadmin-tool to turn on ssh service and gain ssh access
- Connect to ssh server ==> restreint shell
- Escape restreint shell with nano command or ftp command
- Exploit sysadmin-tool with escaping a chroot jail ==> Get root shell
- Exploit worp game : use buffer overflow 


# Prime

Keys : wfuzz, php://filter/, wordpress, md5sum, od, AES encryption, ubuntu 16.04

- Scan directory web service
- Enumerate parameter for pages web
- Discovery LFI on a web page
- Found a password
- Scan wordpress with wpscan found username
- Login wordpress with account : victor/follow_the_ippsec
- Upload php reverse shell
- Found saket's password
- Get root with sudo -l
- Get with exploit kenel version Ubuntu 16.04.4

