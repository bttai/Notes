└─$ sudo nmap -sT -A -T4 -Pn -n  -p- 192.168.110.151
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-12 15:19 CEST
Nmap scan report for 192.168.110.151
Host is up (0.00085s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE VERSION
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          35307/tcp   status
|   100024  1          37398/udp6  status
|   100024  1          48231/udp   status
|_  100024  1          52107/tcp6  status
35307/tcp open  status  1 (RPC #100024)
65535/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u2 (protocol 2.0)
| ssh-hostkey: 
|   1024 f3:53:9a:0b:40:76:b1:02:87:3e:a5:7a:ae:85:9d:26 (DSA)
|   2048 9a:a8:db:78:4b:44:4f:fb:e5:83:6b:67:e3:ac:fb:f5 (RSA)
|   256 c1:63:f1:dc:8f:24:81:82:35:fa:88:1a:b8:73:40:24 (ECDSA)
|_  256 3b:4d:56:37:5e:c3:45:75:15:cd:85:00:4f:8b:a8:5e (ED25519)
MAC Address: 08:00:27:19:D7:77 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.85 ms 192.168.110.151

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.84 seconds




└─$ sudo nmap -sT -A  -Pn -n  -p- 192.168.110.151
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-12 15:36 CEST
Nmap scan report for 192.168.110.151
Host is up (0.00073s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Initech Cyber Consulting, LLC
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          35307/tcp   status
|   100024  1          37398/udp6  status
|   100024  1          48231/udp   status
|_  100024  1          52107/tcp6  status
35307/tcp open  status  1 (RPC #100024)
65535/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u2 (protocol 2.0)
| ssh-hostkey: 
|   1024 f3:53:9a:0b:40:76:b1:02:87:3e:a5:7a:ae:85:9d:26 (DSA)
|   2048 9a:a8:db:78:4b:44:4f:fb:e5:83:6b:67:e3:ac:fb:f5 (RSA)
|   256 c1:63:f1:dc:8f:24:81:82:35:fa:88:1a:b8:73:40:24 (ECDSA)
|_  256 3b:4d:56:37:5e:c3:45:75:15:cd:85:00:4f:8b:a8:5e (ED25519)
MAC Address: 08:00:27:19:D7:77 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.73 ms 192.168.110.151

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.86 seconds
