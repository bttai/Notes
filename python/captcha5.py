import requests
import hashlib
try:
    from PIL import Image
except ImportError:
    import Image
import pytesseract

from lxml import html

from lxml.html import parse, fromstring
import os  


dict = {
"4a5c4c5016a65432e90e46187095a215": "hacker",
"62678b6aef2c55af91fbdf98ce1d4237": "0dayz",
"62678b6aef2c55af91fbdf98ce1d4237": "0dayz",
"64f0d6a64d2a4177380b150fd8700461": "pentester",
"a23fd7db01720aabee7a1fdf54796556" : "vulnerability",
"b549bc8bcb1c81098c23708f0da892c0" : "security",
"f20123b911a1a2425e86b3a512583ae0": "admin",
"f7e205669e4a7ed16f7b5a89f2614898": "compromise"
    
}

l_image = []
l_md5 = []
i = 0
while True:
    # print("get")
    r = requests.get('http://10.0.1.11/captcha/example5/')
    cookies = r.cookies.get_dict()
    tree = fromstring(r.content)
    img_captcha = tree.xpath("//img/@src")[0] 
    # print(tree)
    img_url = "http://10.0.1.11/captcha/example5/" + img_captcha
    captcha = requests.get(img_url)
    # print(img_url)
    with open('captcha.png', 'wb') as file:
        file.write(captcha.content)

    md5hash = hashlib.md5(Image.open('captcha.png').tobytes())
    md5hash = md5hash.hexdigest()
    if md5hash in l_md5:
        # print(len(l_md5)) 
        i = i + 1
    else:
        l_md5.append(md5hash)
        l_image.append(img_captcha)   
        os.rename('captcha.png', md5hash+'.png') 
        
    if i > 200:
        break
print(l_md5)
print(l_image)        

# captcha = pytesseract.image_to_string(Image.open('captcha.png'))
# captcha = captcha.strip()


# data = {"captcha":captcha, "submit": "Submit Query"}

# r = requests.get('http://10.0.1.11/captcha/example6/submit?', params=data, cookies=cookies)

# print(captcha)
# print(r.url)
# print(r.content)  
