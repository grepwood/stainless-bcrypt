/* Copyright 2024 - 2025, Michał Dec */
/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bcrypt.h"

int main(void) {
	int incorrectness = 0;
	size_t rounds = 10;
	const char * prefix = "2b";
	size_t counter = 0;
	size_t key_length = 512;
	char * password_data = "examples";
	size_t password_length = strlen(password_data);
	char * salt_data = NULL;
	size_t salt_length = 0;
	char * hash_data = NULL;
	size_t hash_length = 0;
	size_t kdf_length = 0;
	char * kdf_data = NULL;
	static const char * binary_truth[2] = {"False", "True"};
	size_t binary_truth_selector = 0;

	printf("Input test parameters\n\tPassword:\t%s\n\tRounds:\t\t%zu\n\tVersion:\t%s\n\tLength:\t\t%zu\n\n", password_data, rounds, prefix, key_length);

	salt_data = gensalt(rounds, prefix);
	if (salt_data != NULL) {
		printf("Salt:\t\t\t%s\n", salt_data);
		salt_length = strlen(salt_data);
	} else {
		puts("Salt generation failed.");
		return 1;
	}
	hash_length = hashpw(password_data, password_length, salt_data, salt_length, &hash_data);
	if(hash_data != NULL) {
		printf("Hash:\t\t\t%s\n", hash_data);
	} else {
		puts("Hash generation failed.");
		free(salt_data);
		return 2;
	}
	incorrectness = checkpw(password_data, password_length, hash_data, hash_length);
	binary_truth_selector = !incorrectness;
	printf("Comparison result:\t%s\n", binary_truth[binary_truth_selector]);
	if(incorrectness != 0) {
		puts("bcrypt.checkpw failed");
		free(salt_data);
		free(hash_data);
		return 4;
	}
	kdf_length = kdf(password_data, password_length, salt_data, salt_length, key_length, rounds, 0, &kdf_data);
	if(kdf_length) {
		printf("Key:\t\t\t");
		for(counter = 0; counter < kdf_length; ++counter) {
			printf("%02x", (unsigned char)kdf_data[counter]);
		}
		puts("");
	} else {
		puts("bcrypt.kdf generation failed.");
		free(salt_data);
		free(hash_data);
		free(kdf_data);
		return 8;
	}
	free(salt_data);
	free(hash_data);
	free(kdf_data);
	return 0;
}
