#!/usr/bin/env python3
# Copyright 2024 - 2025, Michał Dec
# SPDX-License-Identifier: Apache-2.0
import sys
import getopt
import traceback
import bcrypt

def usage():
	print(sys.argv[0] + ' -r rounds -v version -p password -l length')
	print("\t-r - specifies the amount of iteration rounds")
	print("\t-v - specifies salt version")
	print("\t-p - specifies password ot work with")
	print("\t-l - desired key length")
	return -1

def main():
	rounds = None
	version = None
	password = None
	length = None
	try:
		opts, argv = getopt.getopt(sys.argv[1:], 'hr:v:p:l:')
	except getopt.GetoptError:
		traceback.print_exc()
		print("")
		return usage()
	for key, value in opts:
		if key == '-h':
			return usage()
		if key == '-r':
			rounds = value
		if key == '-v':
			version = value
		if key == '-p':
			password = value
		if key == '-l':
			length = value
	try:
		assert rounds != None
		assert version != None
		assert password != None
		assert length != None
		assert rounds.isdigit()
		assert length.isdigit()
		rounds = int(rounds)
		length = int(length)
		version = str.encode(version)
		password = str.encode(password)
	except:
		rounds = 10
		version = b'2b'
		length = 512
		password = b'examples'

	print('Input test parameters')
	print("\tPassword:\t" + password.decode('utf-8'))
	print("\tRounds:\t\t" + str(rounds))
	print("\tVersion:\t" + version.decode('utf-8'))
	print("\tLength:\t\t" + str(length) + "\n")

	salt = bcrypt.gensalt(rounds, version)
	print("Salt:\t\t\t" + salt.decode('utf-8'))
	assert type(salt) is bytes
	assert len(salt) == 29

	hashed_password = bcrypt.hashpw(password, salt)
	print("Hash:\t\t\t" + hashed_password.decode('utf-8'))
	assert type(hashed_password) is bytes
	assert len(hashed_password) == 60

	comparison = bcrypt.checkpw(password, hashed_password)
	print("Comparison result:\t" + str(comparison))
	assert comparison

	kdf = bcrypt.kdf(password, salt, length, rounds, False)
	print("Key:\t\t\t" + kdf.hex())
	assert type(kdf) is bytes
	assert len(kdf) == length

if __name__ == '__main__':
	result = main()
	sys.exit(result)
