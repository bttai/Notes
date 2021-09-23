import requests
import hashlib
try:
    from PIL import Image
except ImportError:
    import Image
import pytesseract

from lxml import html
import cv2

from lxml.html import parse, fromstring


r = requests.get('http://10.0.1.11/captcha/example7')
cookies = r.cookies.get_dict()
tree = fromstring(r.content)
# print(tree)
img_url = "http://10.0.1.11/captcha/example7/" + tree.xpath("//img/@src")[0]
captcha = requests.get(img_url)
# print(img_url)
with open('captcha.png', 'wb') as file:
    file.write(captcha.content)

img = cv2.imread('captcha.png',0)

ret, thresh_img = cv2.threshold(img, 100, 220, cv2.THRESH_BINARY_INV)
# cv2.imshow('grey image',thresh_img)
cv2.imwrite("captcha1.png", thresh_img)
captcha = pytesseract.image_to_string(Image.open('captcha1.png'))
captcha = captcha.strip()
data = {"captcha":captcha, "submit": "Submit Query"}
r = requests.get('http://10.0.1.11/captcha/example7/submit?', params=data, cookies=cookies)
print(f'{captcha}')
print(r.url)
print(r.content)  

