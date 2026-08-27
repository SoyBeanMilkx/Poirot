#ifndef POIROT_CRYPTO_MD5_H
#define POIROT_CRYPTO_MD5_H

#include <stddef.h>
#include <stdint.h>

#define MD5_BLOCK_SIZE 64
#define MD5_DIGEST_SIZE 16

struct md5_context {
	uint32_t state[4];
	uint64_t size;
	uint8_t block[MD5_BLOCK_SIZE];
	size_t used;
};

void md5_init(struct md5_context *context);
void md5_update(struct md5_context *context, const void *data, size_t size);
void md5_final(struct md5_context *context,
	       uint8_t digest[MD5_DIGEST_SIZE]);
uint64_t md5_u64(uint64_t input);

#endif
