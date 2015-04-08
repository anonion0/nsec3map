/*
 * Some of this code is based on sha1_gen_fmt_plug.c by Solar Designer
 */

#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"nsec3"
#define FORMAT_NAME			"DNSSEC NSEC3"
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		125

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

#define BINARY_SIZE			20
#define N3_MAX_SALT_SIZE		255
#define N3_MAX_ZONE_SIZE		255


#define HASH_LENGTH			20
#define SALT_SIZE			sizeof(struct salt_t)

struct salt_t {
	uint16_t iterations;
	size_t salt_length;
	size_t zone_length;
	unsigned char salt[N3_MAX_SALT_SIZE];
	unsigned char zone_wf[N3_MAX_ZONE_SIZE];
};

static struct fmt_tests tests[] = {
	{ "$NSEC3$100$4141414141414141$8c2d583acbe22616c69bb457e0c2111ced0a6e77$example.com.", "www" },
	{ "$NSEC3$100$42424242$8fb38d13720815ed5b5fcefd973e0d7c3906ab02$example.com.", "mx" },
	{ NULL }
};


static struct salt_t saved_salt;
/* length of the saved label, without the length field */
static int saved_key_length;
static unsigned char saved_key[PLAINTEXT_LENGTH + 1];
static unsigned char saved_wf_label[PLAINTEXT_LENGTH + 2];

static SHA_CTX sha_ctx;
static ARCH_WORD_32 crypt_out[5];

static void convert_label_wf(void)
{
	int last_dot = saved_key_length - 1;
	int i;
	unsigned char *out = saved_wf_label;
	if (saved_key_length == 0)
		return;
	++out;
	for (i = last_dot ; i >= 0; ) {
		if (saved_key[i] == '.') {
			out[i] = (unsigned char)(last_dot - i); 
			last_dot = --i;
		} else {
			out[i] = tolower(saved_key[i]);
			--i;
		}
	}
	*(--out) = (unsigned char)(last_dot - i);
}

static size_t parse_zone(char *zone, unsigned char *zone_wf_out)
{
	char *lbl_end, *lbl_start;
	unsigned int lbl_len;
	unsigned int index = 0;
	unsigned int zone_len = strlen(zone);

	/* TODO: unvis */
	if (zone_len == 0) {
		return 0;
	} else if (zone_len > N3_MAX_ZONE_SIZE) {
		return 0;
	} 

	lbl_end = strchr(zone, '.');
	lbl_start = zone;
	while (lbl_end != NULL) {
		lbl_len = lbl_end - lbl_start;
		zone_wf_out[index] = (unsigned char) lbl_len;
		if (lbl_len > 0) {
			memcpy(&zone_wf_out[++index], lbl_start, lbl_len);
		}
		index += lbl_len;
		lbl_start = lbl_end+1;
		if (lbl_start - zone == zone_len) {
			zone_wf_out[index] = 0;
			break;
		} else {
			lbl_end = strchr(lbl_start, '.');
		}
	}
	if (lbl_end == NULL)
		return 0;
	return index + 1;
}


/* format:
 * $NSEC3$iter$salt$hash$zone
 */

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	char *p, *q;
	int i;
	unsigned char zone[N3_MAX_ZONE_SIZE];
	unsigned int iter;

	if (strncmp(ciphertext, "$NSEC3$", 7))
		return 0;
	p = ciphertext;
	for (i = 0; i < 4; ++i) {
		p = strchr(p, '$');
		if (p == NULL || *(++p) == 0)
			return 0;
		switch (i) {
		case 0:
			continue;
		case 1:
			/* iterations */
			iter = atoi(p);
			if (iter < 0 || iter > UINT16_MAX)
				return 0;
			break;
		case 2:
			/*  salt */
			q = p;
			while (atoi16[ARCH_INDEX(*q)] != 0x7F)
				++q;
			if (*q != '$' || q-p > N3_MAX_SALT_SIZE*2 || (q-p) % 2)
				return 0;
			break;
		case 3:
			/* hash */
			q = p;
			while (atoi16[ARCH_INDEX(*q)] != 0x7F)
				++q;
			if (*q != '$' || q-p > HASH_LENGTH*2)
				return 0;
			p = q+1;
			break;
		}
	}
	/* zone */
	if (*p== 0)
		return 0;
	if (parse_zone(p, zone) == 0) {
		return 0;
	}
	return 1;
}

static void *get_binary(char *ciphertext)
{
	static unsigned char out[BINARY_SIZE];
	char *p;
	int i;

	p = ciphertext;
	for (i = 0; i < 4; ++i) {
		p = strchr(p, '$') + 1;
	}

	for (i = 0; i < sizeof(out); ++i) {
		out[i] = (atoi16[ARCH_INDEX(*p)] << 4) |
			atoi16[ARCH_INDEX(p[1])];
		p += 2;
	}
	return out;
}

static void *salt(char *ciphertext)
{
	static struct salt_t out;
	unsigned int salt_length;
	int i;
	char *p, *q;

	memset(&out, 0, sizeof(out));
	p = ciphertext;
	for (i = 0; i < 2; ++i) 
		p = strchr(p, '$') + 1;
	out.iterations = (uint16_t) atoi(p);

	p = strchr(p, '$') + 1;
	q = strchr(p, '$'); 
	salt_length = q-p;
	for (i = 0; i < salt_length; i += 2) {
		out.salt[i/2] = (atoi16[ARCH_INDEX(*p)] << 4 |
				atoi16[ARCH_INDEX(p[1])]);
		p += 2;
	}
	out.salt_length = (unsigned char)((salt_length)/2);

	p = strchr(q+1, '$') + 1;
	out.zone_length =  parse_zone(p, out.zone_wf);

	return &out;
}


static int salt_hash(void *salt)
{
	unsigned int hash = 0;
	int i;
	for (i = 0; i < SALT_SIZE; ++i) {
		hash <<= 1;
		hash += (unsigned char)((unsigned char *)salt)[i];
		if (hash >> 10) {
			hash ^= hash >> 10;
			hash &= 0x3FF;
		}
	}
	hash ^= hash >> 10;
	hash &= 0x3FF;

	return hash;
}

static void set_salt(void *salt)
{
	memcpy(&saved_salt, salt, SALT_SIZE);
}

static void set_key(char *key, int index)
{
	saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key, key, saved_key_length);
	convert_label_wf();
}

static  char *get_key(int index)
{
	int i;
	saved_key[saved_key_length] = 0;
	for (i = 0; i < saved_key_length; ++i) {
		saved_key[i] = tolower(saved_key[i]);
	}
	return (char *) saved_key;
}

static void crypt_all(int count)
{
	register int i = 0;
	register uint16_t iterations = saved_salt.iterations;
	register size_t salt_length =  saved_salt.salt_length;

	SHA1_Init(&sha_ctx);
	if (saved_key_length > 0)
		SHA1_Update(&sha_ctx, saved_wf_label, saved_key_length+1);
	SHA1_Update(&sha_ctx, saved_salt.zone_wf, saved_salt.zone_length);
	SHA1_Update(&sha_ctx, saved_salt.salt, salt_length);
	SHA1_Final((unsigned char *)crypt_out, &sha_ctx);
	while (i++ < iterations) {
		SHA1_Init(&sha_ctx);
		SHA1_Update(&sha_ctx, crypt_out, BINARY_SIZE);
		SHA1_Update(&sha_ctx, saved_salt.salt, salt_length);
		SHA1_Final((unsigned char *)crypt_out, &sha_ctx);
	}
}

static int cmp_all(void *binary, int count)
{
	return !memcmp(binary, crypt_out, BINARY_SIZE);
}

static int cmp_exact(char *source, int index) { return 1; }

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32 *)binary & 0xF; } 
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFF; } 
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFFF; } 
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFFFF; } 
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32 *)binary & 0xFFFFF; } 
static int get_hash_0(int index) { return crypt_out[0] & 0xF; } 
static int get_hash_1(int index) { return crypt_out[0] & 0xFF; } 
static int get_hash_2(int index) { return crypt_out[0] & 0xFFF; } 
static int get_hash_3(int index) { return crypt_out[0] & 0xFFFF; } 
static int get_hash_4(int index) { return crypt_out[0] & 0xFFFFF; }

struct fmt_main fmt_nsec3_gen = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		0,
		tests
	}, {
		fmt_default_init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4
		},
		salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4
		},
		cmp_all,
		cmp_all,
		cmp_exact
	}
};
