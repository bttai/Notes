$ sudo fdisk -l
$ sudo dd if=/isos/ubuntu-18.04.3-live-server-amd64.iso of=/dev/sdb bs=1M status=progress

https://www.kali.org/docs/virtualization/install-virtualbox-host/
sudo apt update
sudo apt full-upgrade -y
[ -f /var/run/reboot-required ] && sudo reboot -f

kali@kali:~$ wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- \
  | gpg --dearmor \
  | sudo tee /usr/share/keyrings/virtualbox-archive-keyring.gpg
kali@kali:~$ echo "deb [arch=amd64 signed-by=/usr/share/keyrings/virtualbox-archive-keyring.gpg] http://download.virtualbox.org/virtualbox/debian buster contrib" \
  | sudo tee /etc/apt/sources.list.d/virtualbox.list

sudo apt update
sudo apt install -y dkms
sudo apt install -y virtualbox virtualbox-ext-pack

# vmware Player

```bash
# uname -a                                                                               
Linux kali 5.16.0-kali7-amd64 #1 SMP PREEMPT Debian 5.16.18-1kali1 (2022-04-01) x86_64 GNU/Linux
CPATH=/usr/lib/gcc/x86_64-linux-gnu/11/include vmware-modconfig --console --install-all
```