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

	#Or you can do it in single command
	$ iptables -F

	# Save 
	$ iptables-save > /etc/sysconfig/iptables
	$ iptables-save > /etc/iptables/rules.v4
