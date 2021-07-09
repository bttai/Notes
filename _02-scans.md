=Reconnaissance


Web
└─$ dirb http://192.168.53.128 -X .php,.txt

└─$ nikto -h http://192.168.53.128                 
└─$ gobuster dir -u http://192.168.53.128 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt
└─$ wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt  --hc 404  http://192.168.53.128/index.php?FUZZ=something 
└─$ wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt --hc 404 --hh 197   http://192.168.53.128/image.php?secrettier360=FUZZ

dirsearch


Samba

https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/

nmblookup -A 192.168.1.17
nbtscan 192.168.1.17
nmap --script nbstat.nse 192.168.1.17
smbmap -H 192.168.1.40
CMS


https://www.hackingarticles.in/5-ways-directory-bruteforcing-web-server/

1) dirb http://192.168.1.5/dvwa
2) Dirbuster
	- wordlist : /usr/share/dirbuster/wordlis/ directory-list-2-3-medium.txt
	- dir to start : /dvwa
	- File extension : php
3) wfuzz -c -W /usr/share/wfuzz/wordlist/dir/common.txt --hc 400,404,403 http://192.168.1.5/dvwa/FUZZ
4) Metasploit
	use auxiliary/scanner/http/dir_scanner   
	msf auxiliary(dir_scanner) >set dictionary /usr/share/wordlists/dirb/common.txt
	msf auxiliary(dir_scanner) >set rhosts 192.168.1.5
	msf auxiliary(dir_scanner) > set path /dvwa
	msf auxiliary(dir_scanner) >exploit
5) dirsearch.py –u http://192.18.1.5/dvwa -e php -f -x 400,403,404	