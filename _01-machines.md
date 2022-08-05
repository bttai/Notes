# Relativity ***

Keys : ProFTPD 1.2.8 - 1.2.9 mod_sql, php wrappers data://text/plain;base64, UnrealIRCd, sudo -l

- Exploit ProFTPD mod_sql ==> Discovery web directory
- Exploit php wrapper data://text/plain ==> copy isa private key
- Connect to ssh server ==> Discovery UnrealIRCd. This version containt a backdoor
- Exploit UnrealIRCd server ==> Gain access's another user
- Modify script execute with root privilege to gain root shell


# Pipe *****

Keys : method http, .htaccess <Limit></Limit>, php serialization, php destructor, exploiting wildcard, tar Wildcard Injection


- Scan web service ==> found web hidden directory
- Test different http method ==> found web hidden directory
- Read souce code in a .bak file
- Exploit php destructor to gain reverse shell
- Discovery crontab execute by root user to backup the data with tar command
- Exploit tar wildcard to get root


# Sleepy *****

Keys : Java Debug Wire Protocol (JDWP) version 1.6 1.7.0_71, tomcat, Apache Tomcat Proxy, shellshock, bash-4.2

- Exploit JDWP to copy _/etc/tomcat/tomcat-users.xml_ to _/var/ftp/pub/_
- Read tomcat-users.xml with the ftp service
- Install Apache Tomcat Proxy
- Upload shell with "Manager App"
- Upgrade shell
- Exploit shellshock to gain root shell

# K2 *****


Keys: shared libraries, cat -v, bash -p, ruby gem which, sudo 1.8.6p7, privilege increase with SHELLOPTS and PS4

- Connect to ssh server with user/password
- Exploit shared libraries in C ==> gain user2's access
- Discovery task on crontab hidden by ^[[3A
- Modify ruby library 'gem which zip' ==> gain user3's access
- Exploit suid program by using SHELLOPTS and PS4 on bash 4.2 ==> get root bash shell



# Persistence *****


Keys : ping exfiltration,  escaping from limited bash (ftp, nano), escaping a chroot jail, buffer overflow, canary protection

- Scan web server ==> found debug.php
- Command injection with debug.php. Use ping exfiltration ==> found sysadmin-tool in the root web directory
- Execute sysadmin-tool to turn on ssh service and gain ssh access
- Connect to ssh server ==> restreint shell
- Escape restreint shell with nano command or ftp command
- Exploit sysadmin-tool with escaping a chroot jail ==> Get root shell
- Exploit worp game : use buffer overflow 


# Prime *****

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

# EVM

Keys : wordpress, 4.4.0-87-generic, eBPF_verifier

- Scan and brute force _wordpress_ with wpscan and _rockyou.txt_
- Upload shell
- Found root password on a text file
- Exploit kernel te gain root

# DeRPnStiNK

Keys : wordpress, slideshow gallery, john, tcpdump, modify suid script

- Scan web service with dirsearch ==> wordpress installed in a directory
- wpscan ==> plugin slideshow-gallery is vulnerable
- Upload php web shell
- Found hash in wordpress db
- Crack password with _john_
- Gain stinky's access
- Found mrderp's password in a pcap file
- Login with mrderp account, sudo -l
- Modify the script and get root with sudo command


# Breach-1

Keywords: impresscms, Java KeyStore, keytool, openssl, burp suite, tomcat, sudo -l, decrypting https traffic, wireshark, portspoof

- Found an account hidden in a web page
- Found a password hidden in an image
- Found a keystore in the portail with the pass
- Found a pcap file in the portail
- Decrypt https traffic with wireshark ==> Found the path and account to access tomcat application manager
- Upload a web shell
- Gain to access local with the password found
- Gain root with sudo -l script


# Breach-2

Keywords: firefox 15, blogphp, os commerce, beef-xss, sshd_config, SSH ForceCommand, .bashrc, .profile , sudoers, telnet, xss attack


# Breach-3



# Bob ***

Keywords : bash_aliases, web shell, command injection, gpg, AES encrypted data

- Found a web shell with posibility of command injection,
- Found password in `.old_passwordfile.html`,
- Decode a file encrypted with a password `ARPOCRATES` found from `notes.sh`,
- Get root shell from sudo command from user `bob`

# Replay ****

Keywords: python programmation, nuitka, python compiler, hardcoded, backdoor, modify hard code in a binary

- File `client.bin` found on the web service,
- A backdoor, hardcode is included in it,
- Modify the code, gain shell,
- Found the bob's password on a text file `notes.txt`,
- Get root with `sudo -l`

# Rotating *****

Keywords : web cookies, Caesar cipher, morse code, wfuzz, knock port

- Flag 1 : change value of `isAdmin` in cookie,
- Flag 2 : found password in `loki.bin`,
- Decoded messges with Caesar cipher and found the value of `wheel_code`,
- Turned the wheel by changing the value of `wheel_code`,
- Found others indices and knock port at a serials of ports,
- Get a one-way shell,
- Upload a reverse shell or meterpreter shell,
- Get `zeus`'s' password,
- Get root with sudo command

# Born2root-1

Keysword : impresscms, Java KeyStore, keytool, openssl, burp suite, tomcat, sudo -l, decrypting https traffic, wireshark, portspoof


# Born2root-2

Keysword : joomla, brute force, python, curl, wfuzz

- Brute force joomla `admin:travel`, script python, bash, wfuzz
- Upload reverse shell
- Found tim's password in `/opt/scripts/fileshare.py`
- sudo -l with tim'a account




