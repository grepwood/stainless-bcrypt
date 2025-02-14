/* Copyright 2024 - 2025, Michał Dec */
/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
/* OpenSSL backend */
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
/* Required for MISRA */
#include <stdint.h>

#define SALT_SIZE 16

static char * base64_encode(
	const char * input,
	const int length
) {
	BUF_MEM * buffer = NULL;
	BIO * b64 = NULL;
	BIO * bio = NULL;
	size_t counter;
	const size_t final_size = ((length/3 + (length%3 > 0)) << 2) - (3-length%3)%3;
	char * b64text_without_padding = NULL;
	char branchless_helper[2] = {0, '.'};

	if(input == NULL) {
		fputs("bcrypt.base64_encode: null input.\n", stderr);
		return NULL;
	}

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, input, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &buffer);
	b64text_without_padding = malloc(final_size + 1);
	if(b64text_without_padding == NULL) {
		fprintf(stderr, "bcrypt.base64_encode: memory allocation for output failed.\n");
		BIO_free_all(bio);
		return NULL;
	}
	if(buffer->data == NULL) {
		fprintf(stderr, "bcrypt.base64_encode: something went completely wrong and the buffer is null.\n");
		BIO_free_all(bio);
		return NULL;
	}
	memcpy(b64text_without_padding, buffer->data, final_size);
	b64text_without_padding[final_size] = '\0';
	BIO_free_all(bio);
	for(counter = 0; counter < final_size; ++counter) {
		branchless_helper[0] = b64text_without_padding[counter];
		b64text_without_padding[counter] = branchless_helper[(b64text_without_padding[counter] == '+')];
	}
	return b64text_without_padding;
}

char * gensalt(size_t rounds, const char * version) {
/* I don't know if anyone will try to touch this with MSVC 2012 or older, but
 * I would like to extend this proverbial olive branch to them and make sure
 * this code does not have mixed declarations from C99. */
	char * final_version = NULL;
	static const char * acceptable_versions[3] = {"2a", "2b", "2y"};
	int correct = 0;
	size_t counter = 0;
	char salt[SALT_SIZE];
	char * encoded_salt = NULL;
	size_t final_size;
	char * final_salt = NULL;
	size_t version_length;
	const char * version_src;

/* If we got null inputs, set some sane defaults:
 * - rounds: 12
 * - version: "2b" */
	if(!rounds) rounds = 12;
	if(version == NULL) version = acceptable_versions[1];

/* Next, we have to see if our version is within specified, acceptable
 * parameters. Because there is no "x in y" in C, we have to do a for loop with
 * binary or over a variable initialized as 0, to catch any instance where the
 * comparison returns a favorable result. */
	while(counter < 2) correct |= (!memcmp(version, acceptable_versions[counter++], 2));

/* I have no idea how to do a Raise in C, so this if will have to do.
 * I hope Python can catch it. */
	if(!correct) {
		fprintf(stderr, "bcrypt.gensalt: supported versions are b'2a' or b'2b', b'2y' is cast to b'2b'\n");
		return final_salt;
	}

	if(!memcmp(acceptable_versions[2], version, 2)) version_src = acceptable_versions[1];
	else version_src = version;
	version_length = strlen(version_src);
	final_version = malloc(version_length + 1);
	memcpy(final_version, version_src, version_length);
	final_version[version_length] = '\0';

/* Now let's check the round amount. */
	correct = !(rounds < 4 || rounds > 31);
	if(!correct) {
		fprintf(stderr, "bcrypt.gensalt: invalid rounds\n");
		free(final_version);
		return NULL;
	}
	

/* Alright, the gauntlet is finished, we can continue with actual work.
   All should be hunky dory. */

/* Let's set our salt. */
	memset(salt, 0, SALT_SIZE);
	if (RAND_bytes((uint8_t *)salt, SALT_SIZE) != 1) {
		fprintf(stderr, "Error generating random bytes.\n");
		return final_salt;
	}

/* Next, let's encode the salt in base64. */
	encoded_salt = base64_encode(salt, SALT_SIZE);

/* We can now allocate memory for the final result and snprintf it. */
	final_size = 1 + strlen(final_version) + 1 + 2 + 1 + strlen(encoded_salt);
	final_salt = malloc(final_size + 1);
	snprintf(final_salt, final_size + 1, "$%s$%lu$%s", final_version, rounds, encoded_salt);
/* Free the memory, and return safely. */
	free(final_version);
	free(encoded_salt);
	return final_salt;
}
