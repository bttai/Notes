
```bash

#bash scan_ip.sh

for ip in $(seq 1 254); do
ping -c 1 192.168.110.$ip | grep "bytes from" | cut -d " " -f 4 | cut -d ":" -f 1 &
done




```
```bash

for ip in 1 192.168.110.{1..254}; do ping -c 1 $ip > /dev/null && echo "${ip} is up"; done

```
```bash

#!/bin/bash
TF=$(mktemp -u)
touch $TF
is_alive_ping()
{
  ping -c 1 $1 > /dev/null
  [ $? -eq 0 ] && echo Node with IP: $i is up. >> $TF
}

for i in 192.168.0.{1..254} 
do
is_alive_ping $i & disown
done
sleep 1
cat $TF
rm $TF


```


## Open ports inbound


```bash

for i in $(seq 1 65535); do nc -z -v 192.168.3.50 $i 2>&1 | grep 'open'; done
for i in $(seq 1 65535); do nc -nvz -w 1 192.168.212.4 $i 2>&1; done | grep -v "refused"

```
