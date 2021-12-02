https://www.vulnhub.com/entry/breach-301,177/

https://www.hackingarticles.in/snmp-lab-setup-and-penetration-testing/


https://evi1r0s3.github.io/vulnhub/2020/11/09/Breach_3.0.1.html


Third in a multi-part series, Breach 3.0 is a slightly longer boot2root/CTF challenge which attempts to showcase a few real-world scenarios/vulnerabilities, with plenty of twists and trolls along the way.

Difficulty: Intermediate, requires some creative thinking and persistence more so than advanced exploitation.

The VM is configured to grab a lease via DHCP.

A few things:

1) This is the culmination of the series, keep your notes close from the previous 2 challenges, they may come in handy. 
2) Remember that recon is an iterative process. Make sure you leave no stone unturned. 
3) The VM uses KVM and QEMU for virtualization. It is not necessary to root every host to progress. 
4) There are 3 flags throughout, once you reach a flag you have achieved that intended level of access and can move on. These 3 flags are your objectives and it will be clear once you have found each and when it is time to move on.



# nmap


	$ sudo nmap -sU 192.168.110.10
	Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-01 14:15 CET
	Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
	UDP Scan Timing: About 2.50% done; ETC: 14:16 (0:00:39 remaining)
	Nmap scan report for 192.168.110.10
	Host is up (0.00048s latency).
	Not shown: 999 open|filtered udp ports (no-response)
	PORT    STATE SERVICE
	161/udp open  snmp
	MAC Address: 08:00:27:1E:75:57 (Oracle VirtualBox virtual NIC)

	Nmap done: 1 IP address (1 host up) scanned in 17.69 seconds




	└─$ sudo nmap -sV -sU -p 161 192.168.110.10                                                                                    
	Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-01 14:17 CET
	Nmap scan report for 192.168.110.10
	Host is up (0.00015s latency).

	PORT    STATE SERVICE VERSION
	161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
	MAC Address: 08:00:27:1E:75:57 (Oracle VirtualBox virtual NIC)
	Service Info: Host: Initech-DMZ01

	Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 0.68 seconds


	└─$ sudo nmap -sU -p 161 --script "snmp-*" 192.168.110.10
	Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-01 14:40 CET
	Nmap scan report for 192.168.110.10
	Host is up (0.00012s latency).

	PORT    STATE SERVICE
	161/udp open  snmp
	| snmp-info: 
	|   enterprise: net-snmp
	|   engineIDFormat: unknown
	|   engineIDData: ad610f2abb4d5b5800000000
	|   snmpEngineBoots: 20
	|_  snmpEngineTime: 40m29s
	| snmp-brute: 
	|_  public - Valid credentials
	| snmp-sysdescr: Linux Initech-DMZ01 4.4.0-45-generic #66~14.04.1-Ubuntu SMP Wed Oct 19 15:05:38 UTC 2016 x86_64
	|_  System uptime: 40m30.28s (243028 timeticks)
	MAC Address: 08:00:27:1E:75:57 (Oracle VirtualBox virtual NIC)

	Nmap done: 1 IP address (1 host up) scanned in 16.27 seconds


	$ snmpwalk -c public -v1 -t 10  192.168.110.10
	iso.3.6.1.2.1.1.1.0 = STRING: "Linux Initech-DMZ01 4.4.0-45-generic #66~14.04.1-Ubuntu SMP Wed Oct 19 15:05:38 UTC 2016 x86_64"
	iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
	iso.3.6.1.2.1.1.3.0 = Timeticks: (293426) 0:48:54.26
	iso.3.6.1.2.1.1.4.0 = STRING: "Email: Milton@breach.local - (545)-232-1876"
	iso.3.6.1.2.1.1.5.0 = STRING: "Initech-DMZ01"
	iso.3.6.1.2.1.1.6.0 = STRING: "Initech - is this thing on? I doubt anyone thinks to look here, anyways, I've left myself a way back in and burn the place down once again."
	iso.3.6.1.2.1.1.8.0 = Timeticks: (1) 0:00:00.01
	iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.11.3.1.1
	iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.15.2.1.1
	iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.10.3.1.1
	iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
	iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.2.1.49
	iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.4
	iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
	iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.6.3.16.2.2.1
	iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
	iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
	iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The MIB for Message Processing and Dispatching."
	iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The management information definitions for the SNMP User-based Security Model."
	iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The SNMP Management Architecture MIB."
	iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
	iso.3.6.1.2.1.1.9.1.3.5 = STRING: "The MIB module for managing TCP implementations"
	iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing IP and ICMP implementations"
	iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
	iso.3.6.1.2.1.1.9.1.3.8 = STRING: "View-based Access Control Model for SNMP."
	iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
	iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
	iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (0) 0:00:00.00
	iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (0) 0:00:00.00
	iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (0) 0:00:00.00
	iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (0) 0:00:00.00
	iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (1) 0:00:00.01
	iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (1) 0:00:00.01
	iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (1) 0:00:00.01
	iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (1) 0:00:00.01
	iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (1) 0:00:00.01
	iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (1) 0:00:00.01
	iso.3.6.1.2.1.25.1.1.0 = Timeticks: (294923) 0:49:09.23
	iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E5 0C 01 09 30 23 00 2D 05 00 
	iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
	iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/boot/vmlinuz-4.4.0-45-generic root=UUID=56e63cea-5a5c-4f59-babf-fdd403f70674 ro tty12 quiet splash
	"
	iso.3.6.1.2.1.25.1.5.0 = Gauge32: 0
	iso.3.6.1.2.1.25.1.6.0 = Gauge32: 34
	iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
	End of MIB


	snmpwalk -c public -v1 192.168.110.10 1.3.6.1.4.1.77.1.2.25

	for community in public private manager; do snmpwalk -c $community -v1 192.168.110.10; done
	for community in public private manager; do echo $community; done


	snmpwalk -c public -v1 192.168.110.10 1.3.6.1.2.1.1.9.1.3.2 # enumerate windows users
										  1.3.6.1.2.1.1.9.1.3.2


for p in 545 232 1876; do echo nc -zv 192.168.110.10 $p; done