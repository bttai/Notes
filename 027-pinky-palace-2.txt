https://hackso.me/pinkys-palace-v2-walkthrough/
https://d7x.promiselabs.net/2018/04/10/ctf-pinkys-palace-v2-hard-vulnhub-ctf-walkthrough/

└─$ sudo nmap -sT -A -Pn -n -p- 172.16.227.131
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-27 13:51 CEST
Nmap scan report for 172.16.227.131
Host is up (0.00092s latency).
Not shown: 65531 closed ports
PORT      STATE    SERVICE VERSION
80/tcp    open     http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Database Error
4655/tcp  filtered unknown
7654/tcp  filtered unknown
31337/tcp filtered Elite
MAC Address: 00:0C:29:94:2C:E0 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.92 ms 172.16.227.131



└─$ dirb http://pinkydb                                                                   255 ⨯

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Apr 27 13:58:51 2021
URL_BASE: http://pinkydb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://pinkydb/ ----
+ http://pinkydb/index.php (CODE:500|SIZE:251)                                                 
==> DIRECTORY: http://pinkydb/secret/                                                          
+ http://pinkydb/server-status (CODE:403|SIZE:295)                                             
==> DIRECTORY: http://pinkydb/wordpress/                                                       
==> DIRECTORY: http://pinkydb/wp-admin/                                                        
==> DIRECTORY: http://pinkydb/wp-content/                                                      
==> DIRECTORY: http://pinkydb/wp-includes/      

└─$ curl http://172.16.227.133/secret/bambam.txt       
8890
7000
666

pinkydb


└─$ cat permutations_ports.py 
from itertools import permutations

ports = [666, 7000, 8890]

perm = permutations(ports)

for i in list(perm):
        print(i)

└─$ python permutations_ports.py | tr -cd '0-9,\n' | tee  permutation.txt
666,7000,8890
666,8890,7000
7000,666,8890
7000,8890,666
8890,666,7000
8890,7000,666


└─$ cat knock.sh
TARGET=$1

for ports in $(cat permutation.txt); do
        echo "[*] Trying sequence $ports"
        for p in $(echo $ports | tr ',' ' '); do
                nc -n -z -w1 -v $TARGET $p
        done
        sleep 3
        nmap -n -v -Pn -p- -A --reason $TARGET -oN ${ports}.txt
done


└─$ cat 7000,666,8890.txt

# Nmap 7.91 scan initiated Tue Apr 27 16:43:23 2021 as: nmap -n -v -Pn -p- -A --reason -oN 7000,666,8890.txt 172.16.227.249
Nmap scan report for 172.16.227.249
Host is up, received arp-response (0.00049s latency).
Not shown: 65531 closed ports
Reason: 65531 resets
PORT      STATE SERVICE REASON         VERSION
80/tcp    open  http    syn-ack ttl 64 Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Database Error
4655/tcp  open  ssh     syn-ack ttl 64 OpenSSH 7.4p1 Debian 10+deb9u3 (protocol 2.0)
| ssh-hostkey: 
|   2048 ac:e6:41:77:60:1f:e8:7c:02:13:ae:a1:33:09:94:b7 (RSA)
|   256 3a:48:63:f9:d2:07:ea:43:78:7d:e1:93:eb:f1:d2:3a (ECDSA)
|_  256 b1:10:03:dc:bb:f3:0d:9b:3a:e3:e4:61:03:c8:03:c7 (ED25519)
7654/tcp  open  http    syn-ack ttl 64 nginx 1.10.3
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.10.3
|_http-title: 403 Forbidden
31337/tcp open  Elite?  syn-ack ttl 64
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, NULL, RPCCheck: 
|     [+] Welcome to The Daemon [+]
|     This is soon to be our backdoor
|     into Pinky's Palace.
|   GetRequest: 
|     [+] Welcome to The Daemon [+]
|     This is soon to be our backdoor
|     into Pinky's Palace.
|     HTTP/1.0
|   HTTPOptions: 
|     [+] Welcome to The Daemon [+]
|     This is soon to be our backdoor
|     into Pinky's Palace.
|     OPTIONS / HTTP/1.0
|   Help: 
|     [+] Welcome to The Daemon [+]
|     This is soon to be our backdoor
|     into Pinky's Palace.
|     HELP
|   RTSPRequest: 
|     [+] Welcome to The Daemon [+]
|     This is soon to be our backdoor
|     into Pinky's Palace.
|     OPTIONS / RTSP/1.0
|   SIPOptions: 
|     [+] Welcome to The Daemon [+]
|     This is soon to be our backdoor
|     into Pinky's Palace.
|     OPTIONS sip:nm SIP/2.0
|     Via: SIP/2.0/TCP nm;branch=foo
|     From: <sip:nm@nm>;tag=root
|     <sip:nm2@nm2>
|     Call-ID: 50000
|     CSeq: 42 OPTIONS
|     Max-Forwards: 70
|     Content-Length: 0
|     Contact: <sip:nm@nm>
|_    Accept: application/sdp
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31337-TCP:V=7.91%I=7%D=4/27%Time=60882313%P=x86_64-pc-linux-gnu%r(N
SF:ULL,59,"\[\+\]\x20Welcome\x20to\x20The\x20Daemon\x20\[\+\]\n\0This\x20i
SF:s\x20soon\x20to\x20be\x20our\x20backdoor\n\0into\x20Pinky's\x20Palace\.
SF:\n=>\x20\0")%r(GetRequest,6B,"\[\+\]\x20Welcome\x20to\x20The\x20Daemon\
SF:x20\[\+\]\n\0This\x20is\x20soon\x20to\x20be\x20our\x20backdoor\n\0into\
SF:x20Pinky's\x20Palace\.\n=>\x20\0GET\x20/\x20HTTP/1\.0\r\n\r\n")%r(SIPOp
SF:tions,138,"\[\+\]\x20Welcome\x20to\x20The\x20Daemon\x20\[\+\]\n\0This\x
SF:20is\x20soon\x20to\x20be\x20our\x20backdoor\n\0into\x20Pinky's\x20Palac
SF:e\.\n=>\x20\0OPTIONS\x20sip:nm\x20SIP/2\.0\r\nVia:\x20SIP/2\.0/TCP\x20n
SF:m;branch=foo\r\nFrom:\x20<sip:nm@nm>;tag=root\r\nTo:\x20<sip:nm2@nm2>\r
SF:\nCall-ID:\x2050000\r\nCSeq:\x2042\x20OPTIONS\r\nMax-Forwards:\x2070\r\
SF:nContent-Length:\x200\r\nContact:\x20<sip:nm@nm>\r\nAccept:\x20applicat
SF:ion/sdp\r\n\r\n")%r(GenericLines,5D,"\[\+\]\x20Welcome\x20to\x20The\x20
SF:Daemon\x20\[\+\]\n\0This\x20is\x20soon\x20to\x20be\x20our\x20backdoor\n
SF:\0into\x20Pinky's\x20Palace\.\n=>\x20\0\r\n\r\n")%r(HTTPOptions,6F,"\[\
SF:+\]\x20Welcome\x20to\x20The\x20Daemon\x20\[\+\]\n\0This\x20is\x20soon\x
SF:20to\x20be\x20our\x20backdoor\n\0into\x20Pinky's\x20Palace\.\n=>\x20\0O
SF:PTIONS\x20/\x20HTTP/1\.0\r\n\r\n")%r(RTSPRequest,6F,"\[\+\]\x20Welcome\
SF:x20to\x20The\x20Daemon\x20\[\+\]\n\0This\x20is\x20soon\x20to\x20be\x20o
SF:ur\x20backdoor\n\0into\x20Pinky's\x20Palace\.\n=>\x20\0OPTIONS\x20/\x20
SF:RTSP/1\.0\r\n\r\n")%r(RPCCheck,5A,"\[\+\]\x20Welcome\x20to\x20The\x20Da
SF:emon\x20\[\+\]\n\0This\x20is\x20soon\x20to\x20be\x20our\x20backdoor\n\0
SF:into\x20Pinky's\x20Palace\.\n=>\x20\0\x80")%r(DNSVersionBindReqTCP,59,"
SF:\[\+\]\x20Welcome\x20to\x20The\x20Daemon\x20\[\+\]\n\0This\x20is\x20soo
SF:n\x20to\x20be\x20our\x20backdoor\n\0into\x20Pinky's\x20Palace\.\n=>\x20
SF:\0")%r(DNSStatusRequestTCP,59,"\[\+\]\x20Welcome\x20to\x20The\x20Daemon
SF:\x20\[\+\]\n\0This\x20is\x20soon\x20to\x20be\x20our\x20backdoor\n\0into
SF:\x20Pinky's\x20Palace\.\n=>\x20\0")%r(Help,5F,"\[\+\]\x20Welcome\x20to\
SF:x20The\x20Daemon\x20\[\+\]\n\0This\x20is\x20soon\x20to\x20be\x20our\x20
SF:backdoor\n\0into\x20Pinky's\x20Palace\.\n=>\x20\0HELP\r\n");
MAC Address: 00:0C:29:94:2C:E0 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Uptime guess: 198.840 days (since Sat Oct 10 20:33:45 2020)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.49 ms 172.16.227.249

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Apr 27 16:43:37 2021 -- 1 IP address (1 host up) scanned in 14.24 seconds


sudo nmap -sT -A -Pn -n -p- 172.16.227.133


wpscan --url http://pinkydb/wordpress/ -e u -P /usr/share/wordlists/rockyou.txt 


from itertools import permutations

ports = [666, 7000, 8890]

perm = permutations(ports)

for i in list(perm):
	print(i)


python -c 'import itertools;print(list(itertools.permutations([8890,7000,666])))' | sed 's/), /\n/g' | tr -cd '0-9,\n' | sort | uniq > permutation.txt



nc -n  172.16.227.214 7000
nc -n  172.16.227.214 666
nc -n  172.16.227.214 8890
sudo nmap -sT -A -Pn -n -p- 172.16.227.205


└─$ dirb http://pinkydb:7654        

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Apr 27 17:20:06 2021
URL_BASE: http://pinkydb:7654/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://pinkydb:7654/ ----
+ http://pinkydb:7654/index.php (CODE:200|SIZE:134)                                            
                                                                                               
-----------------
END_TIME: Tue Apr 27 17:20:10 2021
DOWNLOADED: 4612 - FOUND: 1
  


  The credential (pinky:Passione) is the right one. Awesome.