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