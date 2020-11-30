import os
import sys
import getopt
import binascii
import hashlib
import numpy
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.fernet import Fernet

infile_name = ''
ofile1_name = ''
ofile2_name = ''
dictionary_name = ''

def main(argv):

	#this chunk handles input
	opts, args = getopt.getopt(argv,"hd:i:o::")
	for opt, arg in opts:
   		if opt == '-h':
   			print("python bloom_filter.py -d <dictionary> -i <input> -o <outputfile1> <outputfile2>")
   			sys.exit()
   		elif opt in ("-d"):
   			dictionary_name = arg
   		elif opt in ("-i"):
   			infile_name = arg
   		elif opt in ("-o"):
   			ofile1_name = arg
   			ofile2_name = sys.argv[7]

   	#this chunk prints / tests input
	print("dictionary = " + dictionary_name)
	print("infile = " + infile_name)
	print("ofile1 = " + ofile1_name)
	print("ofile2 = " + ofile2_name)

	#open files
	infile = open(infile_name, "r")
	ofile1 = open(ofile1_name, "w+")
	ofile2 = open(ofile2_name, "w+")
	dictionary = open(dictionary_name, "r")

	#find out how many passwords to check
	passwords = 0								#how many passwords to check
	passwords = infile.readline()				#first line of input file, now gone (good)
	passwords = passwords.rstrip()
	passwords = int(passwords)

	bit3 =  [False for i in range(1000000)] 
	bit5 =  [False for i in range(1000000)] 

	#arrays to append to to use to set values of bit3 and bit5
	bits3 = []
	bits5 = []
	
	#go through dictionary.txt...
	print("Creating bloom filters, this will take a few seconds...")
	for line in dictionary:
		#strip newline
		line = line.rstrip()		#get rid of trailing newline	
		line = bytes(line)			#convert to bytes for hashing purposes
		#first hash md5...
		num = line					#set this value (don't want to actually change line bc we use it again)
		num = hashlib.md5(num)		#hash
		num = num.hexdigest()		#to hex
		num = int(num, 16)			#to int
		num = num % 1000000			#to position
		bit3[num] = True			#set position in bit3 to set
		bit5[num] = True			#set position in bit5 to set
		#second hash sha224...
		num = line					#set this value (don't want to actually change line bc we use it again)
		num = hashlib.sha224(num)	#hash
		num = num.hexdigest()		#to hex
		num = int(num, 16)			#to int
		num = num % 1000000			#to position
		bit3[num] = True			#set position in bit3 to set
		bit5[num] = True			#set position in bit5 to set
		#third hash sha256...
		num = line					#set this value (don't want to actually change line bc we use it again)
		num = hashlib.sha256(num)	#hash
		num = num.hexdigest()		#to hex
		num = int(num, 16)			#to int
		num = num % 1000000			#to position
		bit3[num] = True			#set position in bit3 to set
		bit5[num] = True			#set position in bit5 to set
		#fourth hash sha384...
		num = line					#set this value (don't want to actually change line bc we use it again)
		num = hashlib.sha384(num)	#hash
		num = num.hexdigest()		#to hex
		num = int(num, 16)			#to int
		num = num % 1000000			#to position
		bit5[num] = True			#set position in bit5 to set
		#fifth hash sha512...
		num = line					#set this value (don't want to actually change line bc we use it again)
		num = hashlib.sha512(num)	#hash
		num = num.hexdigest()		#to hex
		num = int(num, 16)			#to int
		num = num % 100000			#to position
		bit5[num] = True			#set position in bit5 to set	

	print("Bloom filters created!")
	print("Checking passwords...")
	#check passwords
	for line in infile:
		arr3 = []					#for checking the bit3 bloom
		arr5 = []					#for bit5
		line = line.rstrip()		#remove newline
		#first hash md5
		num = line					#set this value (don't want to actually change line bc we use it again)
		num = hashlib.md5(num)		#hash
		num = num.hexdigest()		#to hex
		num = int(num, 16)			#to int
		num = num % 1000000			#to position
		arr3.append(num)			#add to arr3 array
		arr5.append(num)			#add to arr5 array
		#second hash sha224
		num = line					#set this value (don't want to actually change line bc we use it again)
		num = hashlib.sha224(num)	#hash
		num = num.hexdigest()		#to hex
		num = int(num, 16)			#to int
		num = num % 1000000			#to position
		arr3.append(num)			#add to arr3 array
		arr5.append(num)			#add to arr5 array
		#third hash sha256
		num = line					#set this value (don't want to actually change line bc we use it again)
		num = hashlib.sha256(num)	#hash
		num = num.hexdigest()		#to hex
		num = int(num, 16)			#to int
		num = num % 1000000			#to position
		arr3.append(num)			#add to arr3 array
		arr5.append(num)			#add to arr5 array
		#fourth hash sha384
		num = line					#set this value (don't want to actually change line bc we use it again)
		num = hashlib.sha384(num)	#hash
		num = num.hexdigest()		#to hex
		num = int(num, 16)			#to int
		num = num % 1000000			#to position
		arr5.append(num)			#add to arr5 array
		#fifth hash sha512
		num = line					#set this value (don't want to actually change line bc we use it again)
		num = hashlib.sha512(num)	#hash
		num = num.hexdigest()		#to hex
		num = int(num, 16)			#to int
		num = num % 1000000			#to position
		arr5.append(num)			#add to arr5 array
		#check...
		if (bit3[arr3[0]] and bit3[arr3[1]] and bit3[arr3[2]]):
			ofile1.write("maybe\n")
			if (bit5[arr5[3]] and bit5[arr5[4]]):
				ofile2.write("maybe\n")
			else:
				ofile2.write("no\n")
		else:
			ofile1.write("no\n")
			ofile2.write("no\n")

	print("Passwords checked! Check files " + ofile1_name + " and " + ofile2_name + " for outputs")

	#close files
	infile.close()
	ofile1.close()
	ofile2.close()
	dictionary.close()

#main ends
#define it tho
if __name__ == "__main__":
	main(sys.argv[1:])