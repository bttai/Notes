# hydra

## Basic authentification

	$ hydra -l admin  -p darkweb2017-top100.txt  192.168.56.5 http-get

# dirsearch

	$ dirsearch -u http://192.168.56.5 -w directory-list-2.3-medium.txt

# wfuzz

	$ wfuzz  -c -z file,directory-list-2.3-medium.txt --sc 200 http://192.168.56.5/FUZZ/
	$ wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt  --hc 404 http://website.com/secret.php?FUZZ=something

# dirb
	$ dirb http://192.168.53.128 -X .php,.txt

# iptables

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



	# Save 
	$ iptables-save > /etc/sysconfig/iptables
	$ iptables-save > /etc/iptables/rules.v4


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

















