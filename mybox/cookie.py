#!/usr/bin/python3

import requests
url='http://172.16.16.129/dvwa'
cookies = requests.session().get(url+'/login.php').cookies.get_dict()
for k, v in cookies.items():
    print("%s=%s"%(k,v),end=';')