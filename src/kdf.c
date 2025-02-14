/* Copyright 2024 - 2025, Michał Dec */
/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Meat and bones from OpenSSL */
#include <openssl/evp.h>

#define STACK_STRIDE 8
#define BHASH_WORDS 8
#define BHASH_OUTPUT_SIZE (BHASH_WORDS << 2)
static size_t bcrypt_pbkdf2(
	const char * password_data,
	const int password_length,
	const char * salt_data,
	const int salt_length,
	const int desired_key_length,
	const int rounds,
	char ** result_data
) {
	size_t result_length = 0;
	char * vector_buffer = NULL;
	char * generated = NULL;
	char stack_buffer[STACK_STRIDE * BHASH_OUTPUT_SIZE];
	int e = 0;
	size_t generated_length = BHASH_OUTPUT_SIZE;
	size_t counter;
	size_t chunk_number;
	size_t chunk_index;
	size_t stride = (desired_key_length + BHASH_OUTPUT_SIZE - 1) / BHASH_OUTPUT_SIZE;
/* I have no idea why the original Rust code does this but whatever */
	if(stride > STACK_STRIDE) {
		vector_buffer = calloc(stride, BHASH_OUTPUT_SIZE);
		if(vector_buffer == NULL) {
			return result_length;
		}
		generated_length *= stride;
		generated = vector_buffer;
	} else {
		memset(stack_buffer, 0, STACK_STRIDE * BHASH_OUTPUT_SIZE);
		generated_length *= STACK_STRIDE;
		generated = stack_buffer;
	}
/* In the original Rust code there used to be a check here for the following
 * condition of failure:
 *   generated_length < stride * BHASH_OUTPUT_SIZE
 * We will not be doing it because it's mathematically impossible to reach these
 * conditions within the scope of this project. Tested with a spreadsheet that
 * goes over every value of generated_length and stride multiplied by
 * BHASH_OUTPUT_SIZE for desired_key_length from 1 to 1048575 which far exceeds
 * the use case of this project. */
	e = PKCS5_PBKDF2_HMAC(password_data, password_length, (unsigned char *)salt_data, salt_length, rounds, EVP_sha512(), generated_length, (unsigned char *)generated);
	if(e != 1) {
		fputs("bcrypt.bcrypt_pbkdf2: PKCS5_PBKDF2_HMAC failed\n", stderr);
		if(vector_buffer != NULL) {
			free(vector_buffer);
		}
		return result_length;
	}
	*result_data = malloc(generated_length);
	if(*result_data == NULL) {
		fputs("bcrypt.bcrypt_pbkdf2: result allocation failed\n", stderr);
		if(vector_buffer != NULL) {
			free(vector_buffer);
		}
		return result_length;
	}
	result_length = generated_length;
	for(counter = 0; counter < generated_length; ++counter) {
		chunk_number = counter % stride;
		chunk_index = counter / stride;
		(*result_data)[counter] = generated[chunk_number * BHASH_OUTPUT_SIZE + chunk_index];
	}
	if(vector_buffer != NULL) {
		free(vector_buffer);
	}
	return result_length;
}

/* KDF = Key Derivation Function */
size_t kdf(
	const char * password_data,
	const size_t password_length,
	const char * salt_data,
	const size_t salt_length,
	const int desired_key_length,
	const int rounds,
	const char ignore_few_rounds,
	char ** result_data
) {
	size_t result_length = 0;
	if(!password_length) {
		fputs("bcrypt.kdf: trivial password_length\n", stderr);
		return result_length;
	}
	if(password_data == NULL) {
		fputs("bcrypt.kdf: password is NULL.\n", stderr);
		return result_length;
	}
	if(salt_data == NULL) {
		fputs("bcrypt.kdf: salt is NULL.\n", stderr);
		return result_length;
	}
	if(!salt_length) {
		fputs("bcrypt.kdf: trivial salt_length\n", stderr);
		return result_length;
	}
	if(desired_key_length < 1 || desired_key_length > 512) {
		fprintf(stderr, "bcrypt.kdf: expected desired_key_bytes within from 1 to 512, instead got: %i\n", desired_key_length);
		return result_length;
	}
	if(rounds < 1) {
		fputs("bcrypt.kdf: rounds must be 1 or more.\n", stderr);
		return result_length;
	}
/* Gauntlet finished. Let's do some real work. */
	if(rounds < 50 && !ignore_few_rounds) {
		fprintf(stderr, "sys:1: UserWarning: Warning: bcrypt.kdf() called with only %i round(s). This few is not secure: the parameter is linear, like PBKDF2.\n", rounds);
	}
	result_length = bcrypt_pbkdf2(password_data, password_length, salt_data, salt_length, desired_key_length, rounds, result_data);
	return result_length;
}
