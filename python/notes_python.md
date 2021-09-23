=Notes Python

==Requests

===

data = {'username':'user1', 'password': 'pentesterlab', "submit": "Submit Query"}
cookies = {"captcha": "hacker"}
r = requests.get('http://10.0.1.11/captcha/example3/submit?', params=data, cookies=cookies)

print(r.url)
print(r.content)  


==urllib
==queue
==thearding

