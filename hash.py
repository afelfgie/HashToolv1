#!/system/bin/python
# -*- coding: utf-8 -*-

#WARNA
R = '\033[31m'
ww = '\033[37m'
Y = '\033[33m'
w = '\033[00m'
i='\033[31m[\033[37m+\033[31m] \033[37m '
#BAHAN 1
import os,sys,time,hashlib,marshal
from time import sleep
#BAHAN 2
from core.ghoff import *
from core.choff import *
from core.banner import *
#BAHAN 3
try:
	from memek.kontol import ngentot
	import kamar
	import adm
	import HackerKontolGoblokBangsat
except ImportError:
	pass

def cls():
	os.system("clear")
def clear():
	if 'linux' or 'unix' in sys.platform:
                cls()
        elif 'win' in sys.platform:
                os.system("cls")
        elif 'darwin' in sys.platform:
                os.sytem("cls")
        else:
                cls()
def keluar():
        cls()
        Banner()
        print " "
        print i+"Thanks For Using HashTool ..."
        print i+"Have a Bad Day ..."
        print i+"Good By ..."
        print ""
        exit()
def info():
        exec(marshal.loads('c\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00@\x00\x00\x00s|\x00\x00\x00d\x00\x00e\x00\x00e\x01\x00e\x02\x00f\x03\x00\x16Z\x03\x00d\x01\x00e\x00\x00e\x01\x00e\x02\x00f\x03\x00\x16Z\x04\x00d\x02\x00e\x00\x00e\x01\x00e\x02\x00f\x03\x00\x16Z\x05\x00d\x03\x00e\x01\x00e\x06\x00e\x01\x00e\x03\x00f\x04\x00\x16GHd\x03\x00e\x01\x00e\x06\x00e\x01\x00e\x04\x00f\x04\x00\x16GHd\x03\x00e\x01\x00e\x06\x00e\x01\x00e\x05\x00f\x04\x00\x16GHd\x04\x00S(\x05\x00\x00\x00s \x00\x00\x00%sCode By  %s: %sGunadiCBR & Yous,\x00\x00\x00%sGithub   %s: %shttps://github.com/afelfgies6\x00\x00\x00%sFacebook %s: %shttps://m.facebook.com/aries.isisas.3s\x0c\x00\x00\x00%s[%s#%s] %sN(\x07\x00\x00\x00t\x01\x00\x00\x00wt\x01\x00\x00\x00Rt\x02\x00\x00\x00wwt\x01\x00\x00\x00at\x01\x00\x00\x00gt\x01\x00\x00\x00ft\x01\x00\x00\x00Y(\x00\x00\x00\x00(\x00\x00\x00\x00(\x00\x00\x00\x00s\x0b\x00\x00\x00<GunadiCBR>t\x08\x00\x00\x00<module>\x01\x00\x00\x00s\n\x00\x00\x00\x13\x01\x13\x01\x13\x01\x15\x01\x15\x01'))
def tya():
	print w+" "
	print "%s[%s1%s] %sGenerate Hash" % (R,Y,R,ww)
	print "%s[%s2%s] %sCrack Hash" % (R,Y,R,ww)
	print "%s[%s3%s] %sUpdate HashTool" % (R,Y,R,ww)
	print "%s[%s0%s] \033[00mExit" % (R,Y,R)
	print w+" "
def main():
	clear()
	Banner()
	info()
	tya()
	try:
		memekontol = raw_input(adm_ngentod)
	except:
		keluar()
	if memekontol == '1':
		ghoff()
	elif memekontol == '2':
		choff()
	elif memekontol == '3':
		updt()
	elif '0' in memekontol:
		keluar()
	else: # jangan coli ...
		p()
		print("%s[%s!%s] %sERROR: %s'%s' what? try again %s!") % (R,y,R,R,w,memekontol,R)
		sleep(1.10)
		main()
##########################
if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		keluar()
##########################
