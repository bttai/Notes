import requests


# <form action="submit" action="get">

#   <img src="captcha.png?t=1613655548.1368444"/ > 
#   Answer: <input type="text" name="captcha"/>
#   <input type="hidden" name="answer" value="Q^S[G\Tk]l"/>
#   <input type="submit" name="submit"/>
# </form>

data = {"captcha":"hacker", "answer": "hacker" ,"submit": "Submit Query"}
r = requests.get('http://10.0.1.11/captcha/example2/submit?', params=data)
print(r.url)
print(r.content)  

