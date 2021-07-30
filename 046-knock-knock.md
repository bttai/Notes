http://barrebas.github.io/blog/2014/10/16/rop-rop-for-knock-knock/
https://leonjza.github.io/blog/2014/10/14/knock-knock-whos-there-solving-knock-knock/
https://blog.knapsy.com/blog/2014/10/16/knock-knock-vm-walkthrough/


Description : 
        - Pretty much thought of a pretty neat idea I hadn't seen done before with a VM, and I wanted to turn it into reality!
        - Your job is to escalate to root, and find the flag.
        - Since I've gotten a few PM's, remember: There is a difference between "Port Unreachable" and "Host Unreachable". DHCP is not broken ;)
        - Gotta give a huge shoutout to c0ne for helping to creating the binary challenge, and rasta_mouse and recrudesce for testing :)
        - Also, gotta thank barrebas who was able to find a way to make things easier... but of course that is fixed with this update! ;)
        - Feel free to hit me up in #vulnhub on freenode -- zer0w1re



└─$ sudo nmap -sT -A -Pn -n -T4 192.168.110.37                                                                                                                                        130 ⨯
[sudo] password for kali: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-22 11:10 CEST
Warning: 192.168.110.37 giving up on port because retransmission cap hit (6).
Stats: 0:04:14 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 37.11% done; ETC: 11:21 (0:07:10 remaining)
Stats: 0:06:02 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 52.24% done; ETC: 11:21 (0:05:31 remaining)
Nmap scan report for 192.168.110.37
Host is up (0.76s latency).
All 1000 scanned ports on 192.168.110.37 are closed (909) or filtered (91)
MAC Address: 08:00:27:67:FB:B5 (Oracle VirtualBox virtual NIC)
Too many fingerprints match this host to give specific OS details
Network Distance: 1 hop

TRACEROUTE
HOP RTT       ADDRESS
1   758.36 ms 192.168.110.37

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 909.50 seconds




└─$ nc 192.168.110.37 1337
[22022, 5628, 59755]
[56080, 40195, 47917]

for x in 56080, 40195, 47917; do nmap -Pn --host-timeout 201 --max-retries 0 -p $x 192.168.110.37; done




 N  2 root@knockknock    Thu Sep 25 12:11   24/813   Cron <root@knockknock> /root/start.sh




Dump of assembler code for function main:
   0x08048924 <+0>:     push   ebp
   0x08048925 <+1>:     mov    ebp,esp
   0x08048927 <+3>:     and    esp,0xfffffff0
   0x0804892a <+6>:     sub    esp,0x10
   0x0804892d <+9>:     cmp    DWORD PTR [ebp+0x8],0x3
   0x08048931 <+13>:    je     0x804893a <main+22>
   0x08048933 <+15>:    call   0x80485ec <banner>
   0x08048938 <+20>:    jmp    0x8048966 <main+66>
   0x0804893a <+22>:    mov    eax,DWORD PTR [ebp+0xc]
   0x0804893d <+25>:    add    eax,0x8
   0x08048940 <+28>:    mov    edx,DWORD PTR [eax]
   0x08048942 <+30>:    mov    eax,DWORD PTR [ebp+0xc]
   0x08048945 <+33>:    add    eax,0x4
   0x08048948 <+36>:    mov    eax,DWORD PTR [eax]
   0x0804894a <+38>:    mov    DWORD PTR [esp+0x4],edx
   0x0804894e <+42>:    mov    DWORD PTR [esp],eax
   0x08048951 <+45>:    call   0x80486e6 <cryptFile>
   0x08048956 <+50>:    test   eax,eax
   0x08048958 <+52>:    je     0x8048966 <main+66>
   0x0804895a <+54>:    mov    DWORD PTR [esp],0x8048b38
   0x08048961 <+61>:    call   0x8048480 <puts@plt>
   0x08048966 <+66>:    mov    eax,0x0
   0x0804896b <+71>:    leave  
   0x0804896c <+72>:    ret    
End of assembler dump.
