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



# tmux

	C-b C-b     Send the prefix
	C-b C-o     Rotate through the panes
	C-b C-z     Suspend the current client
	C-b Space   Select next layout
	C-b !       Break pane to a new window
	C-b "       Split window vertically
	C-b #       List all paste buffers
	C-b $       Rename current session
	C-b %       Split window horizontally
	C-b &       Kill current window
	C-b '       Prompt for window index to select
	C-b (       Switch to previous client
	C-b )       Switch to next client
	C-b ,       Rename current window
	C-b -       Delete the most recent paste buffer
	C-b .       Move the current window
	C-b /       Describe key binding
	C-b 0       Select window 0
	C-b 1       Select window 1
	C-b 2       Select window 2
	C-b 3       Select window 3
	C-b 4       Select window 4
	C-b 5       Select window 5
	C-b 6       Select window 6
	C-b 7       Select window 7
	C-b 8       Select window 8
	C-b 9       Select window 9
	C-b :       Prompt for a command
	C-b ;       Move to the previously active pane
	C-b =       Choose a paste buffer from a list
	C-b ?       List key bindings
	C-b C       Customize options
	C-b D       Choose a client from a list
	C-b E       Spread panes out evenly
	C-b L       Switch to the last client
	C-b M       Clear the marked pane
	C-b [       Enter copy mode
	C-b ]       Paste the most recent paste buffer
	C-b c       Create a new window
	C-b d       Detach the current client
	C-b f       Search for a pane
	C-b i       Display window information
	C-b l       Select the previously current window
	C-b m       Toggle the marked pane
	C-b n       Select the next window
	C-b o       Select the next pane
	C-b p       Select the previous window
	C-b q       Display pane numbers
	C-b r       Redraw the current client
	C-b s       Choose a session from a list
	C-b t       Show a clock
	C-b w       Choose a window from a list
	C-b x       Kill the active pane
	C-b z       Zoom the active pane
	C-b {       Swap the active pane with the pane above
	C-b }       Swap the active pane with the pane below
	C-b ~       Show messages
	C-b DC      Reset so the visible part of the window follows the cursor
	C-b PPage   Enter copy mode and scroll up

# TLDR

Des pense-bêtes pour des milliers de commandes. Pour apprendre rapidement et simplement son usage via des exemples concrets.

	tldr tar












