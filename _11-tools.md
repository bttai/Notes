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




