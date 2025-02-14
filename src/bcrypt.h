/* Copyright 2024 - 2025, Michał Dec */
/* SPDX-License-Identifier: Apache-2.0 */
char * gensalt(
	size_t rounds,
	const char * prefix
);
size_t kdf(
	const char * password_data,
	const size_t password_length,
	const char * salt_data,
	const size_t salt_length,
	const int desired_key_length,
	const int rounds,
	const char ignore_few_rounds,
	char ** result_data
);
int checkpw(
	const char * password_data,
	const size_t password_length,
	const char * hashed_password_data,
	const size_t hashed_password_length
);
size_t hashpw(
	const char * password_data,
	const size_t password_length,
	const char * salt_data,
	const size_t salt_length,
	char ** result_data
);
