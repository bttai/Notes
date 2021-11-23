# hydra

## Basic authentification

	$ hydra -l admin  -p darkweb2017-top100.txt  192.168.56.5 http-get

# dirsearch

	$ dirsearch -u http://192.168.56.5 -w directory-list-2.3-medium.txt

# wfuzz

	$ wfuzz  -c -z file,directory-list-2.3-medium.txt --sc 200 http://192.168.56.5/FUZZ/



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

	sudo tcpdump host 192.168.56.8 -i vboxnet0 and icmp -X
 
# dd
    sudo fdisk -l
    sudo dd bs=1M if=image.iso of=/dev/sdf status=progress conv=fsync




