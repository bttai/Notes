import requests
import hashlib

import re

import lxml.html





import urllib.parse




r = requests.get('http://10.0.1.11/captcha/example9')
cookies = r.cookies.get_dict()

token = re.findall(r'(?:[0-9]|[0-9])+[\+\-\^\*]+(?:[0-9]|[0-9])', str(r.content))

captcha = eval(token[0])
# http://10.0.1.11/captcha/example9/submit?captcha=21&submit=Submit+Query
data = {"captcha":captcha, "submit": "Submit Query"}
payload = urllib.parse.urlencode(data)
print(payload)
# print(data)
r2 = requests.get('http://10.0.1.11/captcha/example9/submit?'+payload, cookies=cookies)
print(r2.url)
print(captcha)
# print(r.content)

# https://stackoverflow.com/questions/43098529/how-to-print-all-text-in-a-specific-tag-using-xpath-in-python
# https://stackoverflow.com/questions/53195927/get-all-text-in-an-lxml-node
tree = lxml.html.fromstring(r2.content)
# node = tree.xpath("//div")[0]
divs = tree.xpath("//div[@class='text-success']//text()")
for el in divs:
    print (el)




# tree = fromstring(r.content)
# # print(tree)
# img_url = "http://10.0.1.11/captcha/example8/" + tree.xpath("//img/@src")[0]
# captcha = requests.get(img_url)
# # print(img_url)
# with open('captcha.png', 'wb') as file:
#     file.write(captcha.content)

# img = cv2.imread('captcha.png',0)

# ret, thresh_img = cv2.threshold(img, 100, 220, cv2.THRESH_BINARY_INV)
# # cv2.imshow('grey image',thresh_img)
# cv2.imwrite("captcha1.png", thresh_img)
# captcha = pytesseract.image_to_string(Image.open('captcha1.png'))
# captcha = captcha.strip()
# data = {"captcha":captcha, "submit": "Submit Query"}
# r = requests.get('http://10.0.1.11/captcha/example8/submit?', params=data, cookies=cookies)
# print(r.url)
# print(r.content)  
# print(f'{captcha}')

