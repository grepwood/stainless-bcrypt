/* Copyright 2024 - 2025, Michał Dec */
/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
/* Backend: we rely on OpenSSL for MOST things.
 * Unfortunately, Blowfish is deprecated in OpenSSL 3.x and will be
 * removed in OpenSSL 4.0. There's this as a means to futureproof our
 * code, but for those who can't use libxcrypt just yet, here's a little
 * olive branch. */
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#ifdef NO_LIBXCRYPT
#	include <openssl/blowfish.h>
#	include <openssl/buffer.h>
#else
#	include <crypt.h>
#endif

#define SALT_SIZE 16

struct bcrypt_result {
	size_t cost;
	char * salt;
	char * hash;
};

struct bcrypt_style_salt {
	char * version;
	size_t rounds;
	char * salt;
};

static struct bcrypt_style_salt * dissect_salt(
	const char * salt_data,
	const size_t salt_length
) {
	size_t counter = 0;
	size_t encountered_dollarsigns = 0;
	size_t * delimiter_offset = NULL;
	size_t dollarsign_counter = 0;
	struct bcrypt_style_salt * result = NULL;
	size_t copy_size = 0;
	uint8_t correctness = (salt_data[0] == '$');

	if(!correctness) {
		fputs("bcrypt.dissect_salt: salt does not begin with a dollar sign.\n", stderr);
		return result;
	}

	while(counter < salt_length) encountered_dollarsigns += (salt_data[counter++] == '$');
	correctness = (encountered_dollarsigns == 3);
	if(!correctness) {
		fputs("bcrypt.dissect_salt: invalid salt.\n", stderr);
		return result;
	}

	delimiter_offset = malloc(sizeof(size_t) * encountered_dollarsigns);
	for(counter = 0; counter < salt_length && dollarsign_counter < encountered_dollarsigns; ++counter) {
		if(salt_data[counter] == '$') {
			delimiter_offset[dollarsign_counter++] = counter;
		}
	}

	result = malloc(sizeof(struct bcrypt_style_salt));
	result->version = NULL;
	result->rounds = 0;
	result->salt = NULL;

	copy_size = delimiter_offset[1] - delimiter_offset[0] - 1;
	result->version = malloc(copy_size + 1);
	memcpy(result->version, (salt_data)+delimiter_offset[0]+1, copy_size);
	result->version[copy_size] = '\0';

	result->rounds = strtol((salt_data)+delimiter_offset[1]+1, NULL, 10);

	copy_size = salt_length - delimiter_offset[2] - 1;
	result->salt = malloc(copy_size + 1);
	memcpy(result->salt, (salt_data)+delimiter_offset[2]+1, copy_size);
	result->salt[copy_size] = '\0';
	free(delimiter_offset);
	return result;
}

static void free_bss(struct bcrypt_style_salt * bss) {
	if(bss != NULL) {
		if(bss->version !=NULL) free(bss->version);
		if(bss->salt !=NULL) free(bss->salt);
		free(bss);
	}
}

#ifdef NO_LIBXCRYPT
static char * base64_encode(const char * input, const int length) {
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

static char * translate_bcrypt_base64_to_normal_base64(const char * bcrypt_base64_input) {
	char branchless_helper[2] = {0, '+'};
	size_t input_length = 0;
	size_t counter = 0;
	size_t normal_base64_length = 0;
	char * normal_base64 = NULL;
	if(bcrypt_base64_input == NULL) {
		return NULL;
	}
	input_length = strlen(bcrypt_base64_input);
	counter = input_length;
	normal_base64_length = input_length + (3 - input_length%3)%3;
	normal_base64 = malloc(normal_base64_length + 1);
	memcpy(normal_base64, bcrypt_base64_input, input_length);
/* We need to add padding bytes: '=' */
	while(counter < normal_base64_length) normal_base64[counter++] = '=';
/* We need to change all dots to pluses. */
	for(counter = 0; counter < input_length; ++counter) {
		branchless_helper[0] = normal_base64[counter];
		normal_base64[counter] = branchless_helper[(normal_base64[counter] == '.')];
	}
/* And before we wrap this up, we null-terminate the string. */
	normal_base64[normal_base64_length] = '\0';
	return normal_base64;
}

static size_t base64_decode(const char * bcrypt_base64_salt, char ** result_data) {
	size_t result_length = 0;
	size_t counter = 0;
	char * b64_text = translate_bcrypt_base64_to_normal_base64(bcrypt_base64_salt);
	size_t b64_length = strlen(b64_text);
	BIO * b64 = BIO_new(BIO_f_base64());
	BIO * bio = BIO_new(BIO_s_mem());
	if (bio == NULL || b64 == NULL) {
		free(b64_text);
		return result_length;
	}
	BIO_write(bio, b64_text, b64_length);
	BIO_push(b64, bio);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	result_length = (b64_length/3) << 1;
	*result_data = malloc(result_length);
	for(counter = 0; counter < result_length; ++counter) {
		BIO_read(b64, (*result_data)+counter, 1);
	}
	free(b64_text);
	BIO_free_all(b64);
	return result_length;
}

static char * bcrypt_encrypt_openssl(
	const size_t rounds,
	const char * salt_data,
	const size_t salt_length,
	const char * password_data,
	const size_t password_length
) {
	static const char seed[24] = {'O','r','p','h','e','a','n','B','e','h','o','l','d','e','r','S','c','r','y','D','o','u','b','t'};
	BF_KEY * state = NULL;
	uint8_t block[8] = {0,0,0,0,0,0,0,0};
	size_t count;
	size_t iterations = 1;
	char * output = NULL;
//	int e = 0;
	uint8_t correctness = !(rounds < 4 || rounds > 31);
	fputs("Blowfish provider:\tOpenSSL\n", stderr);
	if(!correctness) {
		puts("bcrypt.bcrypt_encrypt: wrong roudns");
		return NULL;
	}

	iterations <<= rounds;
	state = malloc(sizeof(BF_KEY));
	if(state == NULL) {
		fputs("bcrypt.bcrypt_encrypt: state memory allocation failed\n", stderr);
		return NULL;
	}
	BF_set_key(state, password_length, (uint8_t *)password_data);
	for(count = 0; count < iterations; ++count) {
		BF_set_key(state, password_length, (uint8_t *)password_data);
		BF_set_key(state, salt_length, (uint8_t *)salt_data);
	}
	output = malloc(24);
	memcpy(output, seed, 24);
	BF_ecb_encrypt(block, (uint8_t *)output, state, BF_ENCRYPT);
	free(state);
	return output;
}
#else
static char * bcrypt_encrypt_libxcrypt(
	const size_t rounds,
	const char * salt_data,
	const char * password_data
) {
	char * hashed_password = NULL;
	char * output = NULL;
	struct crypt_data data;
	uint8_t correctness = !(rounds < 4 || rounds > 31);
	fputs("Blowfish provider:\tlibxcrypt\n", stderr);
	if(!correctness) {
		puts("bcrypt.bcrypt_encrypt: wrong roudns");
		return NULL;
	}
	data.initialized = 0;

	hashed_password = crypt_r(password_data, salt_data, &data);
	if(hashed_password == NULL) {
		fputs("bcrypt.bcrypt_encrypt: password hashing failed\n", stderr);
		return NULL;
	}

	output = strdup(hashed_password);
	if (output == NULL) {
		fputs("bcrypt.bcrypt_encrypt: memory allocation failed\n", stderr);
		return NULL;
	}

    return output;
}
#endif

#ifdef NO_LIBXCRYPT
static struct bcrypt_result * hash_password(
	const char * password_data,
	const size_t password_length,
	const size_t rounds,
	const char * salt_data,
	const size_t salt_length
) {
#else
static struct bcrypt_result * hash_password(
	const char * password_data,
	struct bcrypt_style_salt * dissected_salt,
	const char * salt_data
) {
#endif
	char * output = NULL;
	struct bcrypt_result * result = NULL;
#ifdef NO_LIBXCRYPT
	uint8_t correctness = !(rounds < 4 || rounds > 31);
	if(!correctness) {
		fprintf(stderr, "bcrypt.hash_password: invalid rounds\n");
		return result;
	}
	output = bcrypt_encrypt_openssl(rounds, salt_data, salt_length, password_data, password_length);
#else
	output = bcrypt_encrypt_libxcrypt(dissected_salt->rounds, salt_data, password_data);
#endif
/* The original Rust code used to have a fix for the wraparound bug here, but
 * because we handle it way earlier, it's not needed here. */
	if(output == NULL) {
		fprintf(stderr, "bcrypt.hash_password: encryption failed.\n");
		return NULL;
	}

	result = malloc(sizeof(struct bcrypt_result));
#ifdef NO_LIBXCRYPT
	result->cost = rounds;
	result->salt = base64_encode(salt_data, salt_length);
	result->hash = base64_encode(output, 23);
#else
	result->cost = dissected_salt->rounds;
	result->salt = strdup(dissected_salt->salt);
	result->hash = malloc(32);
	memcpy(result->hash, output + 29, 31);
	result->hash[31] = '\0';
#endif
	free(output);
	return result;
}

static size_t length_of_integer_in_base10(size_t number) {
	size_t counter = 1;
	size_t approximator = 10;
	while(approximator <= number) {
		approximator *= 10;
		++counter;
	}
	return counter;
}

static size_t format_for_version(
	struct bcrypt_result * hash,
	const char * version,
	char ** result_data
) {
	size_t result_length = 0;
	if(version == NULL) {
		fprintf(stderr, "bcrypt.format_for_version: version is null.\n");
		return result_length;
	}
	if(hash == NULL) {
		fprintf(stderr, "bcrypt.format_for_version: hash struct is null.\n");
		return result_length;
	}
	if(!(hash->cost)) {
		fprintf(stderr, "bcrypt.format_for_version: hash cost is null.\n");
		return result_length;
	}
	if(hash->hash == NULL) {
		fprintf(stderr, "bcrypt.format_for_version: actual hash is null.\n");
		return result_length;
	}
	if(hash->salt == NULL) {
		fprintf(stderr, "bcrypt.format_for_version: hash salt is null.\n");
		return result_length;
	}
	result_length = 3 + strlen(version) + length_of_integer_in_base10(hash->cost) + strlen(hash->hash) + strlen(hash->salt);
	*result_data = malloc(result_length + 1);
	snprintf(*result_data, result_length + 1, "$%s$%zu$%s%s", version, hash->cost, hash->salt, hash->hash);
	return result_length;
}

/* We have to truncate the password to 72 bytes due to this bug:
 * https://www.openwall.com/lists/oss-security/2012/01/02/4 */
#define MAXIMUM_PASSWORD_LENGTH 72
static size_t truncate_password(
	const char * password_data,
	const size_t password_length,
	char ** result_data
) {
	static size_t length_closet[2] = {0, MAXIMUM_PASSWORD_LENGTH};
	size_t result_length;
	length_closet[0] = password_length;
	result_length = length_closet[password_length > MAXIMUM_PASSWORD_LENGTH];
	*result_data = malloc(result_length + 1);
	memcpy(*result_data, password_data, result_length);
	(*result_data)[result_length] = '\0';
	return result_length;
}

size_t hashpw(
	const char * password_data,
	const size_t password_length,
	const char * salt_data,
	const size_t salt_length,
	char ** result_data
) {
	static const char * supported_salt_version[4] = {"2y", "2b", "2a", "2x"};
	size_t counter = 0;
	int correctness = 0;
	char * salt_closet = NULL;
	size_t known_good_size_of_salt = 0;
	size_t known_good_size_of_just_the_salt = 0;
	struct bcrypt_style_salt * dissected_salt = NULL;
	size_t result_length = 0;
	struct bcrypt_result * hashed = NULL;
	char * copy_of_salt_data = NULL;
	size_t copy_of_salt_length = 0;
	char * truncated_password_data = NULL;
#ifdef NO_LIBXCRYPT
	size_t truncated_password_length = truncate_password(password_data, password_length, &truncated_password_data);
	char * raw_salt_data = NULL;
	size_t raw_salt_length = 0;
#else
	truncate_password(password_data, password_length, &truncated_password_data);
#endif
	dissected_salt = dissect_salt(salt_data, salt_length);
	known_good_size_of_just_the_salt = ((SALT_SIZE/3 + (SALT_SIZE%3 > 0)) << 2) - (3-SALT_SIZE%3)%3;
	known_good_size_of_salt = 3 + strlen(dissected_salt->version) + length_of_integer_in_base10(dissected_salt->rounds) + known_good_size_of_just_the_salt;

	if(salt_length > known_good_size_of_salt) {
		copy_of_salt_length = known_good_size_of_salt;
		copy_of_salt_data = malloc(copy_of_salt_length + 1);
		memcpy(copy_of_salt_data, salt_data, copy_of_salt_length);
		copy_of_salt_data[copy_of_salt_length] = '\0';

		salt_closet = malloc(known_good_size_of_just_the_salt + 1);
		memcpy(salt_closet, dissected_salt->salt, known_good_size_of_just_the_salt);
		salt_closet[known_good_size_of_just_the_salt] = '\0';

		free(dissected_salt->salt);
		dissected_salt->salt = malloc(known_good_size_of_just_the_salt + 1);
		memcpy(dissected_salt->salt, salt_closet, known_good_size_of_just_the_salt);
		dissected_salt->salt[known_good_size_of_just_the_salt] = '\0';
	} else {
		copy_of_salt_data = malloc(salt_length);
		memcpy(copy_of_salt_data, salt_data, salt_length);
		copy_of_salt_length = salt_length;
	}

	while(counter < 4) correctness |= (!memcmp(dissected_salt->version, supported_salt_version[counter++], 2));
	if(!correctness) {
		fputs("bcrypt.hashpw: unknown salt version.\n", stderr);
		free_bss(dissected_salt);
		if(salt_closet != NULL) {
			free(salt_closet);
			free(copy_of_salt_data);
		}
		return result_length;
	}

#ifdef NO_LIBXCRYPT
	raw_salt_length = base64_decode(dissected_salt->salt, &raw_salt_data);
	hashed = hash_password(truncated_password_data, truncated_password_length, dissected_salt->rounds, raw_salt_data, raw_salt_length);
#else
	hashed = hash_password(truncated_password_data, dissected_salt, copy_of_salt_data);
#endif
	if(hashed == NULL) {
		fputs("bcrypt.hashpw: hash_password failed.\n", stderr);
#ifdef NO_LIBXCRYPT
		free(raw_salt_data);
#endif
		free_bss(dissected_salt);
		if(salt_closet != NULL) {
			free(salt_closet);
			free(copy_of_salt_data);
		}
		return result_length;
	}
#ifdef NO_LIBXCRYPT
	free(raw_salt_data);
#endif
	result_length = format_for_version(hashed, dissected_salt->version, result_data);
	free(hashed->hash);
	free(hashed->salt);
	free(hashed);
	free_bss(dissected_salt);
	if(salt_closet != NULL) {
		free(salt_closet);
		free(copy_of_salt_data);
	}
	return result_length;
}
