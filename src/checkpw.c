/* Copyright 2024 - 2025, Michał Dec */
/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
/* OpenSSL backend */
#include <openssl/crypto.h>

size_t hashpw(
	const char * password_data,
	const size_t password_length,
	const char * salt_data,
	const size_t salt_length,
	char ** result_data
);

static int does_pb_contain_null_terminator(const char * data, const size_t length) {
	size_t counter = 0;
	int result = 0;
	while(counter < length) result |= (data[counter++] == '\0');
	return result;
}

static int hmac_compare_digest(const char * a_data, const size_t a_length, const char * b_data, const size_t b_length) {
	size_t length_closet[2];
	size_t bigger_length;
	int result = -1;
/* Don't allocate the values until we tested the input. */
	if(a_data == NULL) {
		fputs("bcrypt.hmac_compare_digest: a_data is NULL.\n", stderr);
		return result;
	}
	if(!a_length) {
		fputs("bcrypt.hmac_compare_digest: a_length cannot be 0.\n", stderr);
		return result;
	}

	if(b_data == NULL) {
		fputs("bcrypt.hmac_compare_digest: b_data is NULL.\n", stderr);
		return result;
	}

	if(!b_length) {
		fputs("bcrypt.hmac_compare_digest: b_length cannot be 0.\n", stderr);
		return result;
	}
/* Now that all tests are passed, we can do the real work. */
	length_closet[0] = a_length;
	length_closet[1] = b_length;
/* We purposefully want to select the bigger length to drive the test
 * towards failure if the memory regions are not equal in size. But if
 * they are equal and have the same data, everything will be alright. */
	bigger_length = length_closet[(a_length < b_length)];
	result = CRYPTO_memcmp(a_data, b_data, bigger_length);
	return result;
}

int checkpw(const char * password_data, const size_t password_length, const char * hashed_password_data, const size_t hashed_password_length) {
	char * ret_data = NULL;
	size_t ret_length = 0;
	int result = 1;

	if(!password_length) {
		fputs("bcrypt.checkpw: password_length cannot be zero\n", stderr);
		return result;
	}
	if(password_data == NULL) {
		fputs("bcrypt.checkpw: password_data is NULL.\n", stderr);
		return result;
	}
	if(!hashed_password_length) {
		fputs("bcrypt.checkpw: hashed_password_length cannot be zero\n", stderr);
		return result;
	}
	if(hashed_password_data == NULL) {
		fputs("bcrypt.checkpw: hashed_password_data is NULL.\n", stderr);
		return result;
	}
	result = does_pb_contain_null_terminator(password_data, password_length);
	if(result) {
		fputs("bcrypt.checkpw: password contains null terminator.\n", stderr);
		return result;
	}
	result = does_pb_contain_null_terminator(hashed_password_data, hashed_password_length);
	if(result) {
		fputs("bcrypt.checkpw: hashed password contains null terminator.\n", stderr);
		return result;
	}

	puts("Currently in checkpw");
	ret_length = hashpw(password_data, password_length, hashed_password_data, hashed_password_length, &ret_data);
	if(ret_data == NULL) fputs("bcrypt.checkpw: failed to call hashpw.\n", stderr);
	else {
		result = hmac_compare_digest(ret_data, ret_length, hashed_password_data, hashed_password_length);
		free(ret_data);
	}
	return result;
}
