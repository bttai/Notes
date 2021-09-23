import requests
import hashlib
try:
    from PIL import Image
except ImportError:
    import Image
import pytesseract

from lxml import html

from lxml.html import parse, fromstring
r = requests.get('http://10.0.1.11/captcha/example6')
cookies = r.cookies.get_dict()

#https://stackoverflow.com/questions/4061354/using-python-lxml-html-how-can-i-find-images-within-link-tags
# https://stackoverflow.com/questions/5927031/python-get-image-link-from-html

# <img src="captcha.png?t=1613660726.2575748"/ >

# print(r.url)
# print(r.content) 
# tree = html.parse("http://10.0.1.11/captcha/example5")
tree = fromstring(r.content)
# print(tree)
img_url = "http://10.0.1.11/captcha/example6/" + tree.xpath("//img/@src")[0]
captcha = requests.get(img_url)
# print(img_url)
with open('captcha.png', 'wb') as file:
    file.write(captcha.content)


captcha = pytesseract.image_to_string(Image.open('captcha.png'))
captcha = captcha.strip()


data = {"captcha":captcha, "submit": "Submit Query"}

r = requests.get('http://10.0.1.11/captcha/example6/submit?', params=data, cookies=cookies)

print(captcha)
print(r.url)
print(r.content)  
