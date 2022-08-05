

Options -Indexes
AuthUserFile /var/www/html/laudanum/.htpasswd 
AuthName "Please Enter Password" 
AuthType Basic 
Require valid-user



#install apache utilis
sudo apt-get install apache2 apache2-utils
#add apache user
sudo htpasswd -c /etc/apache2/.htpasswd some_username_here

#Setup Directory permissions in Apache Config
<Directory "/var/www/html">
    AuthType Basic
    AuthName "Restricted Content"
    AuthUserFile /etc/apache2/.htpasswd
    Require valid-user
</Directory>
#restart apache
sudo service apache2 restart


wfuzz -c -w users.txt -w passwords.txt --basic FUZZ:FUZ2Z -u http://oscp.local/laudanum/ --hc 401

ffuf -w upbase64.txt -u http://oscp.local/laudanum/ -H "Authorization: Basic FUZZ" -c  -fc 401



dirb  http://oscp.local/laudanum/ -u admin:password -X .php
gobuster dir -u http://oscp.local/laudanum/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --username admin --password  password -x php,txt
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://oscp.local/laudanum/FUZZ -e .php,.txt -H "Authorization: Basic YWRtaW46cGFzc3dvcmQ=" -c  -mc 200

wfuzz --basic admin:password -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://oscp.local/laudanum/FUZZ.php --sc 200

## ffuf_basicauth

```bash
└─$ cat ffuf_basicauth.sh 
#!/bin/sh

##############################################################################
# Script name: ffuf_basicauth.sh
# Description: Generate HTTP basic authentication username:password
#              credential combinations from provided wordlists.
# Author:      Joona Hoikkala
# Email:       joohoi@io.fi
############################################################################## 
# 
# Usage example:
# Test each HTTP basic authentication username:password combination 
# in https://example.org/endpoint, and filter out 403 - Forbidden responses.
# 
# ./ffuf_basicauth.sh usernames.txt passwords.txt |ffuf -w -:AUTH \
#    -u https://example.org/endpoint -H "Authorization: Basic AUTH" -fc 403
#
##############################################################################

if [ "$#" -ne 2 ]; then
    printf "Usage: %s usernames.txt passwords.txt\n" "$0" >&2
    exit 1
fi

if ! [ -f "$1" ]; then
    printf "%s file not found.\n\n" "$1" >&2
    printf "Usage: %s usernames.txt passwords.txt\n" "$0" >&2
    exit 1
fi

if ! [ -f "$2" ]; then
    printf "%s file not found.\n\n" "$2" >&2
    printf "Usage: %s usernames.txt passwords.txt\n" "$0" >&2
    exit 1
fi

USERNAME_WORDLIST="$1"
PASSWORD_WORDLIST="$2"
USERNAME_WORDLIST_SIZE=$(wc -l "$USERNAME_WORDLIST" |awk '{print $1;}')
PASSWORD_WORDLIST_SIZE=$(wc -l "$PASSWORD_WORDLIST" |awk '{print $1;}')
OUTPUT_WORDLIST_SIZE=$((USERNAME_WORDLIST_SIZE * PASSWORD_WORDLIST_SIZE))

printf "\nGenerating HTTP basic authentication strings. This can take a while depending on the length of user and password lists.\n\n" >&2
printf "Usernames: %s\n" "$USERNAME_WORDLIST_SIZE" >&2
printf "Passwords: %s\n" "$PASSWORD_WORDLIST_SIZE" >&2
printf "Total combinations: %s\n\n" "$OUTPUT_WORDLIST_SIZE" >&2

while IFS= read -r user
do
    while IFS= read -r password
    do
        printf "%s:%s" "$user" "$password" |base64
    done < "$PASSWORD_WORDLIST"
done < "$USERNAME_WORDLIST"

```
