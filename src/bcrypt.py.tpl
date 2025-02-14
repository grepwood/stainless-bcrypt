#!/usr/bin/env python3
# Copyright 2024 - 2025, Michał Dec
# SPDX-License-Identifier: Apache-2.0
__all__ = ('gensalt', 'hashpw', 'checkpw', 'kdf')
__version__ = '5.0.0'
__version_info__ = (5, 0, 0)
from cffi import FFI as _FFI
from os.path import abspath as _abspath

_ffi = _FFI()
_dll_path = _abspath('%LIB_INSTALL_DIR%/%DLL_NAME%')
_c_header_path = _abspath('%HEADER_INSTALL_DIR%/bcrypt.h')
_fp = open(_c_header_path, mode='r')
_c_header = ''.join(_fp.readlines())
_fp.close()
_ffi.cdef(_c_header)
_lib = _ffi.dlopen(_dll_path)
_branchless_binary_closet = (b'\x00', b'\x01')

def gensalt(rounds: int = 12, prefix: bytes = b'2b') -> bytes:
	global _ffi
	global _lib
	salt = _lib.gensalt(rounds, prefix)
	result = _ffi.string(salt)
	return result

def hashpw(password: bytes, salt: bytes) -> bytes:
	global _ffi
	global _lib
	password_data = _ffi.new('char []', password)
	password_length = len(password)
	salt_data = _ffi.new('char[]', salt)
	salt_length = len(salt)
	hashed_password_data = _ffi.new('char **')
	hashed_password_length = _lib.hashpw(password_data, password_length, salt_data, salt_length, hashed_password_data)
	result = _ffi.string(hashed_password_data[0], hashed_password_length)
	return result

def checkpw(password: bytes, hashed_password: bytes) -> bool:
	global _ffi
	global _lib
	password_length = len(password)
	password_data = _ffi.new(f'char[{password_length}]', password)
	hashed_password_length = len(hashed_password)
	hashed_password_data = _ffi.new(f'char[{hashed_password_length}]', hashed_password)
	result = not bool(_lib.checkpw(password_data, password_length, hashed_password_data, hashed_password_length))
	return result

def kdf(password: bytes, salt: bytes, desired_key_bytes: int, rounds: int, ignore_few_rounds: bool = False) -> bytes:
	global _ffi
	global _lib
	global _branchless_binary_closet
	password_data = _ffi.new('char[]', password)
	password_length = len(password)
	salt_data = _ffi.new('char[]', salt)
	salt_length = len(salt)
	char_ignore_few_rounds = _branchless_binary_closet[int(ignore_few_rounds)]
	output_data = _ffi.new('char **')
	output_length = _lib.kdf(password_data, password_length, salt_data, salt_length, desired_key_bytes, rounds, char_ignore_few_rounds, output_data)
	result = bytes(_ffi.buffer(output_data[0], output_length))
	return result
