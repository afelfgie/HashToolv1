# -*- coding: utf-8 -*-
#WARNA
R = '\033[31m'
ww = '\033[37m'
Y = '\033[93m'
y = '\033[33m'
W = '\033[00m'
w = '\033[00m'
#BAHAN 1
import os,sys,time,zlib,random,base64,re,itertools,hashlib,binascii
from itertools import cycle
from string import lowercase, uppercase
from time import sleep
#BAHAN 2
try:
    import plib,pbar
except ImportError:
    print("%s[%s-%s] %sERROR%s: %smodule %splib %sand %spbar %sNot Installed %s!" % (R,Y,R,W,R,W,R,W,R,W,R))
    sys.exit()

str_endeop = '''

%s[1] %sEncode%s
[2] %sDecode

%s[*] %sChoice :%s ''' % (R,W,R,W,W,R,W)
l_edr = ['[+] Hash : ',\
         '[*] String : ',\
         '[*] Text to Decode : ']
e = "%s[%s*%s] %sHash   %s>>> %s" % (R,y,R,w,R,w)
q = "%s[%s*%s] %sString %s>>> %s" % (R,y,R,w,R,w)
adm_ngentod = " \033[04mHashTool\033[00m \033[31m>>>\033[00m "
def clear():
	os.system("clear")
def s():
	print " "
def md4():
	s()
	x = raw_input(q)
	m = hashlib.new("md4")
	m.update(x)
	md4 = m.hexdigest()
	print (e+md4)
def md5hash():
	print w+" "
	hash = hashlib.md5(raw_input(q)).hexdigest()
	print "%s[%s*%s] %sHash   %s>>> %s%s" % (R,y,R,w,R,w,hash)
	print w+" "
	exit()
def sha1hash():
	print w+" "
	hash = hashlib.sha1(raw_input(q)).hexdigest()
	print "%s[%s*%s] %sHash   %s>>> %s%s" % (R,y,R,w,R,w,hash)
	quit()
def sha224hash():
	print w+""
	hash = hashlib.sha224(raw_input(q)).hexdigest()
	print "%s[%s*%s] %sHash   %s>>> %s%s" % (R,y,R,w,R,w,hash)
	quit()
def sha256hash():
	print ""
	hash = hashlib.sha256(raw_input(q)).hexdigest()
	print "%s[%s*%s] %sHash   %s>>> %s%s" % (R,y,R,w,R,w,hash)
	quit()
def sha384hash():
	print ""
	hash = hashlib.sha384(raw_input(q)).hexdigest()
	print "%s[%s*%s] %sHash   %s>>> %s%s" % (R,y,R,w,R,w,hash)
	quit()
def sha512hash():
	print " \033[31m"
	hash = hashlib.sha512(raw_input(q)).hexdigest()
	print "%s[%s*%s] %sHash   %s>>> %s%s" % (R,y,R,w,R,w,hash)
def base64hash(i_opt):
    a = [{1:base64.b64encode, 2:base64.b64decode},\
         {1:base64.b32encode, 2:base64.b32decode},\
         {1:base64.b16encode, 2:base64.b16decode}]
    b = int(raw_input(str_endeop))
    print ''
    if (b > 2): sys.exit()
    s = raw_input(l_edr[b])
    print l_edr[0] + a[i_opt][b](s)
    print ""
def ripemd160hash():
	s()
	ls = raw_input(q)
	m = hashlib.new("ripemd160")
	m.update(ls)
	ripemd160 = m.hexdigest()
	print "[*] Hash   >>> %s" % ripemd160
def adler32():
	print ""
	hash = raw_input(q)
	h = zlib.adler32(hash)
	adler32 = '%08X' % (h & 0xffffffff,)
	print "%s[%s*%s] %sHash   %s>>> %s%s" % (R,y,R,w,R,w,adler32.lower())
        quit()
def crc32():
	s()
	hash = raw_input(q)
	h = zlib.crc32(hash)
	crc32 = '%08X' % (h & 0xffffffff,)
	print "%s[%s*%s] %sHash   %s>>> %s%s" % (R,y,R,w,R,w,crc32.lower())
	quit()
def whirlpool():
	s()
	w = raw_input(q)
	l = hashlib.new("whirlpool")
	l.update(w)
	whirlpool = l.hexdigest()
	print "[*] Hash   >>> %s" % whirlpool
	s()
	quit()
def binary():
    a = int(raw_input(str_endeop))
    print ''
    if (a > 2): sys.exit()
    b = raw_input(l_edr[a])
    return a,b
def mysql323():
	s()
	m = raw_input(q)
	from plib.hash import mysql323
	mysql1323 = mysql323.encrypt(m)
	print (e+mysql1323)
def mysql41():
	s()
	m = raw_input(q)
	from passlib.hash import mysql41
	mysql141 = mysql41.encrypt(m)
	print (e+mysql141)
def mssql2000():
	s()
	m = raw_input(q)
	from passlib.hash import mssql2000 as m20
	mssql2000 = m20.encrypt(m)
	print (e+mssql2000)
def mssql2005():
	s()
	m = raw_input(q)
	from passlib.hash import mssql2005 as m25
	mssql2005 = m25.encrypt(m)
	print (e+mssql2005)
def des():
	s()
	m = raw_input(q)
	from passlib.hash import des_crypt
	des = des_crypt.encrypt(m)
	print (e+des)
def bsdicrypt():
	s()
	m = raw_input(q)
	from passlib.hash import bsdi_crypt
	bsdi = bsdi_crypt.encrypt(m)
	print (e+bsdi)
def bigcrypt():
	s()
	m = raw_input(q)
	from passlib.hash import bigcrypt
	big = bigcrypt.encrypt(m)
	print (e+big)
def crypt16():
	s()
	m = raw_input(q)
	from passlib.hash import crypt16
	crypt16 = crypt16.encrypt(m)
	print (e+crypt16)
def md5crypt():
	s()
	m = raw_input(q)
	from passlib.hash import md5_crypt as mc
	md5_crypt = mc.encrypt(m)
	print (e+md5_crypt)
def sha1crypt():
	s()
	m = raw_input(q)
	from passlib.hash import sha1_crypt as mc
	sha1_crypt = mc.encrypt(m)
	print (e+sha1_crypt)
def sha256crypt():
	s()
	m = raw_input(q)
	from passlib.hash import sha256_crypt as mc
	sha256_crypt = mc.encrypt(m)
	print (e+sha256_crypt)
def sha512crypt():
	s()
	m = raw_input(q)
	from passlib.hash import sha512_crypt as mc
	sha512_crypt = mc.encrypt(m)
	print (e+sha512_crypt)
def sunmd5crypt():
	s()
	m = raw_input(q)
	from passlib.hash import sun_md5_crypt as mc
	sun_md5_crypt = mc.encrypt(m)
	print (e+sun_md5_crypt)
def apachemd5crypt():
	s()
	m = raw_input(q)
	from passlib.hash import apr_md5_crypt as mc
	apr_md5_crypt = mc.encrypt(m)
	print (e+apr_md5_crypt)
def phpass():
	s()
	m = raw_input(q)
	from passlib.hash import phpass as mc
	phpass = mc.encrypt(m)
	print (e+phpass)
def cryptacularspbdf2():
	s()
	m = raw_input(q)
	from passlib.hash import cta_pbkdf2_sha1 as mc
	cta_pbkdf2_sha1 = mc.encrypt(m)
	print (e+cta_pbkdf2_sha1)
def dwinepbdf2():
	s()
	m = raw_input(q)
	from passlib.hash import dlitz_pbkdf2_sha1 as mc
	dlitz_pbkdf2_sha1 = mc.encrypt(m)
	print (e+dlitz_pbkdf2_sha1)
def djangosha1():
	s()
	m = raw_input(q)
	from passlib.hash import django_pbkdf2_sha1 as m25
	django_sha1 = m25.encrypt(m)
	print (e+django_sha1)
def djangosha256():
	s()
	m = raw_input(q)
	from passlib.hash import django_pbkdf2_sha256 as m25
	django_sha256 = m25.encrypt(m)
	print (e+django_sha256)
def gruppbkdf2sha512():
	s()
	m = raw_input(q)
	from passlib.hash import grub_pbkdf2_sha512 as m25
	grup_pbkdf2_sha512 = m25.encrypt(m)
	print (e+grup_pbkdf2_sha512)
def all():
	print ""
	try:
		hash = raw_input(q)
	except:
		all()
	clear()
	m4 = hashlib.new("md4")
	m4.update(hash)
	md4 = m4.hexdigest()
	md5 = hashlib.md5(hash.encode()).hexdigest()
	sha1 = hashlib.sha1(hash.encode()).hexdigest()
	sha224 = hashlib.sha224(hash.encode()).hexdigest()
	sha384 = hashlib.sha384(hash.encode()).hexdigest()
	sha512 = hashlib.sha512(hash.encode()).hexdigest()
	sha256 = hashlib.sha256(hash.encode()).hexdigest()
        m = hashlib.new("ripemd160")
        m.update(hash)
        ripemd160 = m.hexdigest()
	h = zlib.adler32(hash)
        adler32 = '%08X' % (h & 0xffffffff,)
	ss = zlib.crc32(hash)
        crc32 = '%08X' % (ss & 0xffffffff,)
        l = hashlib.new("whirlpool")
        l.update(hash)
        whirlpool = l.hexdigest()
        print "%s[%s*%s] %sMD4                %s: %s%s" % (R,Y,R,W,R,W,md4)
        print "%s[%s*%s] %sMD5                %s: %s%s" % (R,Y,R,W,R,W,md5)
        print "%s[%s*%s] %sSHA1               %s: %s%s" % (R,Y,R,W,R,W,sha1)
        print "%s[%s*%s] %sSHA224             %s: %s%s" % (R,Y,R,W,R,W,sha224)
        print "%s[%s*%s] %sSHA256             %s: %s%s" % (R,Y,R,W,R,W,sha256)
	print "%s[%s*%s] %sSHA384             %s: %s%s" % (R,Y,R,W,R,W,sha384)
        print "%s[%s*%s] %sSHA512             %s: %s%s" % (R,Y,R,W,R,W,sha512)
        print "%s[%s*%s] %sADLER32            %s: %s%s" % (R,y,R,w,R,w,adler32.lower())
        print "%s[%s*%s] %sCRC32              %s: %s%s" % (R,y,R,w,R,w,crc32.lower())
        print "%s[%s*%s] %sRipemd160          %s: %s%s" % (R,Y,R,W,R,W,ripemd160)
        print "%s[%s*%s] %sWHIRLPOOL          %s: %s%s" % (R,Y,R,W,R,W,whirlpool)
	from plib.hash import mysql323
        mysql1323 = mysql323.encrypt(hash)
	print "%s[%s*%s] %sMYSQL323           %s: %s%s" % (R,Y,R,W,R,W,mysql1323)
        from plib.hash import mysql41
        mysql141 = mysql41.encrypt(hash)
	print "%s[%s*%s] %sMYSQL41            %s: %s%s" % (R,Y,R,W,R,W,mysql141)
	from plib.hash import mssql2000 as m20
        mssql2000 = m20.encrypt(hash)
	print "%s[%s*%s] %sMSSQL 2000         %s: %s%s" % (R,Y,R,W,R,W,mssql2000)
	from plib.hash import mssql2005 as m25
        mssql2005 = m25.encrypt(hash)
	print "%s[%s*%s] %sMSSQL 2005         %s: %s%s" % (R,Y,R,W,R,W,mssql2005)
	from plib.hash import des_crypt
        des = des_crypt.encrypt(hash)
	print "%s[%s*%s] %sDES                %s: %s%s" % (R,Y,R,W,R,W,des)
	from plib.hash import bsdi_crypt
        bsdi = bsdi_crypt.encrypt(hash)
	print "%s[%s*%s] %sBSDI Crypt         %s: %s%s" % (R,Y,R,W,R,W,bsdi)
	from plib.hash import bigcrypt
        big = bigcrypt.encrypt(hash)
	print "%s[%s*%s] %sBig Crypt          %s: %s%s" % (R,Y,R,W,R,W,big)
	from plib.hash import crypt16
	crypt16 = crypt16.encrypt(hash)
	print "%s[%s*%s] %sCrypt 16           %s: %s%s" % (R,Y,R,W,R,W,crypt16)
	from plib.hash import md5_crypt as mc
        md5_crypt = mc.encrypt(hash)
	print "%s[%s*%s] %sMD5 Crypt          %s: %s%s" % (R,Y,R,W,R,W,md5_crypt)
	from plib.hash import sha1_crypt as mc
        sha1_crypt = mc.encrypt(hash)
	print "%s[%s*%s] %sSHA1 Crypt         %s: %s%s" % (R,Y,R,W,R,W,sha1_crypt)
	from plib.hash import sha256_crypt as mc
        sha256_crypt = mc.encrypt(hash)
	print "%s[%s*%s] %sSHA256 Crypt       %s: %s%s" % (R,Y,R,W,R,W,sha256_crypt)
        from plib.hash import sha512_crypt as mc
        sha512_crypt = mc.encrypt(hash)
        print "%s[%s*%s] %sSHA512 Crypt       %s: %s%s" % (R,Y,R,W,R,W,sha512_crypt)
	from plib.hash import sun_md5_crypt as mc
        sun_md5_crypt = mc.encrypt(hash)
        print "%s[%s*%s] %sSun MD5 Crypt      %s: %s%s" % (R,Y,R,W,R,W,sun_md5_crypt)
	from plib.hash import apr_md5_crypt as mc
        apr_md5_crypt = mc.encrypt(hash)
        print "%s[%s*%s] %sApr MD5 Crypt      %s: %s%s" % (R,Y,R,W,R,W,apr_md5_crypt)
	from plib.hash import phpass as mc
        phpass = mc.encrypt(hash)
        print "%s[%s*%s] %sPHPASS             %s: %s%s" % (R,Y,R,W,R,W,phpass)
	from plib.hash import cta_pbkdf2_sha1 as mc
        cta_pbkdf2_sha1 = mc.encrypt(hash)
        print "%s[%s*%s] %sCTA PBKDF2 SHA1    %s: %s%s" % (R,Y,R,W,R,W,cta_pbkdf2_sha1)
	from plib.hash import dlitz_pbkdf2_sha1 as mc
        dlitz_pbkdf2_sha1 = mc.encrypt(hash)
        print "%s[%s*%s] %sDLITZ PBKDF2 SHA1  %s: %s%s" % (R,Y,R,W,R,W,dlitz_pbkdf2_sha1)
	from plib.hash import django_pbkdf2_sha1 as m25
        django_sha1 = m25.encrypt(hash)
        print "%s[%s*%s] %sDjango SHA1        %s: %s%s" % (R,Y,R,W,R,W,django_sha1)
	from plib.hash import django_pbkdf2_sha256 as m25
        django_sha256 = m25.encrypt(hash)
        print "%s[%s*%s] %sDjango SHA256      %s: %s%s" % (R,Y,R,W,R,W,django_sha256)
	from plib.hash import grub_pbkdf2_sha512 as m25
        grup_pbkdf2_sha512 = m25.encrypt(hash)
	print "%s[%s*%s] %sGrup PBKDF2 SHA512 %s: %s%s" %(R,Y,R,W,R,W,grup_pbkdf2_sha512)
	s()
	os.system('echo "" | busybox timeout -t 3 termux-clipboard-set 2>/dev/null && busybox timeout -t 5 termux-toast "ADM-ngentot | KONTOL-MEMEK | DICK" 2>/dev/null')
	sys.exit()
def l():
	ghoff()
def ghoff():
	print ""
	print "%s[%s*%s] %sAlgorithm%s: %smd4" % (R,y,R,ww,R,Y)
	print "               %smd5" % Y
	print "               %ssha1" % Y
	print "               %ssha224" % Y
	print "               %ssha256" % Y
	print "               %ssha384" % Y
	print "               %ssha512" % Y
	print "               %sbase64" % Y
	print "               %sbase32" % Y
	print "               %sbase16" % Y
	print "               %sripemd160" % Y
	print "               %sadler32" % Y
	print "               %scrc32" % Y
	print "               %swhirlpool" % Y
	print "               %sbinary" % Y
	print "               %shexadecimal" % Y
	print """               mysql323
               mysql41
               mssql2000
               mssql2005
               des
               bsdicrypt
               bigcrypt
               crypt16
               md5crypt
               sha1crypt
               sha256crypt
               sha512crypt
               sunmd5crypt
               aprmd5crypt
               phpass
               cryptacularspbdf2
               dwinepbdf2
               djangosha1
               djangosha256
               gruppbkdf2sha512"""
       	print "               %sall" % Y
	print ""
	try:
		ghoff = raw_input(" \033[93mAlgorithm \033[31m>>>\033[00m ")
	except:
		s()
		print "adm-ngentot"
		quit()
	if ghoff == 'md5' or ghoff == 'MD5':
		md5hash()
	elif ghoff == 'md4':
		md4()
	elif ghoff == 'sha1' or ghoff == 'SHA1':
		sha1hash()
	elif ghoff == 'sha3' or ghoff == 'SHA3':
		md5()
	elif ghoff == 'sha224' or ghoff == 'SHA224':
		sha224hash()
	elif ghoff == 'sha256' or ghoff == 'SHA256':
		sha256hash()
	elif ghoff == 'sha384' or ghoff == 'SHA384':
		sha384hash()
	elif ghoff == 'sha512' or ghoff == 'SHA512':
		sha512hash()
	elif ghoff == 'base64' or ghoff == 'BASE64':
		base64hash(0)
	elif ghoff == 'base32' or ghoff == 'BASE32':
		base64hash(1)
	elif ghoff == 'base16' or ghoff == 'BASE16':
		base64hash(2)
	elif ghoff == 'ripemd160' or ghoff == 'RIPEMD160':
		ripemd160hash()
	elif ghoff == 'blake2s' or ghoff == 'BLAKE2S':
		blake2s()
	elif ghoff == 'blake2b' or ghoff == 'BLAKE2B':
		blake2b()
	elif ghoff == 'adler32':
		adler32()
	elif ghoff == 'crc32':
		crc32()
	elif ghoff == 'whirlpool':
		whirlpool()
	elif ghoff == 'binary':
		o,s = binary()
		print "%s%s" % (l_edr[0], bin(int(binascii.hexlify(s), 16)) if (o == 1) else binascii.unhexlify('%x' % int(s, 2)) if (o == 2) else '')
	elif ghoff == 'hexadecimal':
		o,s = binary()
		print "%s%s" % (l_edr[0], binascii.hexlify(s) if (o == 1) else binascii.unhexlify(s) if (o == 2) else '')
	elif ghoff == 'mysql323':
		mysql323()
	elif ghoff == 'mysql41':
		mysql41()
	elif ghoff == 'mssql2000':
                mssql2000()
        elif ghoff == 'mssql2005':
                mssql2005()
        elif ghoff == 'des':
                des()
        elif ghoff == 'bsdicrypt':
                bsdicrypt()
        elif ghoff == 'bigcrypt':
                bigcrypt()
        elif ghoff == 'crypt16':
                crypt16()
        elif ghoff == 'md5crypt':
                md5crypt()
        elif ghoff == 'sha1crypt':
                sha1crypt()
        elif ghoff == 'sha256crypt':
                sha256crypt()
        elif ghoff == 'sha512crypt':
                sha512crypt()
        elif ghoff == 'sunmd5crypt':
                sunmd5crypt
        elif ghoff == 'apachemd5crypt':
                apachemd5crypt()
        elif ghoff == 'phpass':
                phpass()
        elif ghoff == 'cryptacularspbdf2':
                cryptacularspbdf2()
        elif ghoff == 'djangosha1':
                djangosha1()
        elif ghoff == 'djangosha256':
                djangosha256()
	elif ghoff == 'gruppbkdf2sha512':
		gruppbkdf2sha512()
	elif ghoff == 'all' or ghoff == 'ALL':
		all()
	else:
		clear()
		l()
def updt():
	clear()
	print "%s[%s+%s] %sUpdating HashTool ..." % (R,Y,R,W)
	sleep(1.50)
	os.system("cd ~/ && rm -rf HashTool && git clone https://github.com/afelfgie/HashTool")
	os.system("cd ~/ && cd HashTool && chmod +x hash.py")
	sleep(2)
	s()
	print "%s[%s+%s] %sD%so%sn%se %s.%s.%s." % (R,Y,R,W,Y,W,Y,R,W,Y)
	sys.exit()

