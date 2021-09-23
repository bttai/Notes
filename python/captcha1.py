import requests

data = {"captcha1":"hacker", "submit": "Submit Query"}
r = requests.get('http://10.0.1.11/captcha/example1/submit?', params=data)
print(r.url)
print(r.content)  

