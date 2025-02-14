# Copyright 2024 - 2025, Michał Dec */
# SPDX-License-Identifier: Apache-2.0 */
CC=gcc
CFLAGS=-O2 -fPIC
WARNING_FLAGS=-Wall -Wextra -pedantic -Werror
LINKER_FLAGS=-lcrypt -lcrypto
LEGACY_LINKER_FLAGS=-lcrypto
LEGACY_HELPER_FLAGS=-DNO_LIBXCRYPT -Wno-deprecated-declarations
PYTHON_SUFFIX=$(shell python3-config --extension-suffix)
DLL_NAME=bcrypt$(PYTHON_SUFFIX)
ARCH=$(shell $(CC) -v 2>&1 | grep ^Target: | awk '{print $$2}')
SED=sed

HASHPW_FLAGS=
FINAL_LINKER_FLAGS=$(LINKER_FLAGS)
ifdef NO_LIBXCRYPT
	HASHPW_FLAGS=$(LEGACY_HELPER_FLAGS)
	FINAL_LINKER_FLAGS=$(LEGACY_LINKER_FLAGS)
endif

DEBUG_FLAGS=-ggdb
ifndef DEBUG_BUILD
	DEBUG_FLAGS=
endif

.PHONY: clean all test

all: $(ARCH)/$(DLL_NAME) bcrypt.py

$(ARCH):
	mkdir $(ARCH)

$(ARCH)/checkpw.o: $(ARCH)
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) $(WARNING_FLAGS) -c checkpw.c -o $(ARCH)/checkpw.o

$(ARCH)/gensalt.o: $(ARCH)
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) $(WARNING_FLAGS) -c gensalt.c -o $(ARCH)/gensalt.o

$(ARCH)/hashpw.o: $(ARCH)
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) $(WARNING_FLAGS) $(HASHPW_FLAGS) -c hashpw.c -o $(ARCH)/hashpw.o

$(ARCH)/kdf.o: $(ARCH)
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) $(WARNING_FLAGS) -c kdf.c -o $(ARCH)/kdf.o

$(ARCH)/$(DLL_NAME): $(ARCH)/checkpw.o $(ARCH)/gensalt.o $(ARCH)/hashpw.o $(ARCH)/kdf.o
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) $(WARNING_FLAGS) $(FINAL_LINKER_FLAGS) -shared $(ARCH)/checkpw.o $(ARCH)/gensalt.o $(ARCH)/hashpw.o $(ARCH)/kdf.o -o $(ARCH)/$(DLL_NAME)

bcrypt.py: $(ARCH)/$(DLL_NAME)
	$(SED) \
		"s?%HEADER_INSTALL_DIR%?$(shell pwd)?;\
		s?%LIB_INSTALL_DIR%?$(shell pwd)/$(ARCH)?;\
		s/%DLL_NAME%/$(DLL_NAME)/" \
		bcrypt.py.tpl > bcrypt.py

$(ARCH)/test.o: $(ARCH)
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) $(WARNING_FLAGS) -c test.c -o $(ARCH)/test.o

$(ARCH)/test: $(ARCH)/checkpw.o $(ARCH)/gensalt.o $(ARCH)/hashpw.o $(ARCH)/kdf.o $(ARCH)/test.o
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) $(WARNING_FLAGS) $(FINAL_LINKER_FLAGS) $(ARCH)/checkpw.o $(ARCH)/gensalt.o $(ARCH)/hashpw.o $(ARCH)/kdf.o $(ARCH)/test.o -o $(ARCH)/test

test: $(ARCH)/test

clean:
	rm -f bcrypt.py
	rm -rf $(ARCH)
