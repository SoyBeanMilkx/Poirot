#include "md5.h"

#include <string.h>

static const uint32_t md5_constants[64] = {
	UINT32_C(0xd76aa478), UINT32_C(0xe8c7b756), UINT32_C(0x242070db),
	UINT32_C(0xc1bdceee), UINT32_C(0xf57c0faf), UINT32_C(0x4787c62a),
	UINT32_C(0xa8304613), UINT32_C(0xfd469501), UINT32_C(0x698098d8),
	UINT32_C(0x8b44f7af), UINT32_C(0xffff5bb1), UINT32_C(0x895cd7be),
	UINT32_C(0x6b901122), UINT32_C(0xfd987193), UINT32_C(0xa679438e),
	UINT32_C(0x49b40821), UINT32_C(0xf61e2562), UINT32_C(0xc040b340),
	UINT32_C(0x265e5a51), UINT32_C(0xe9b6c7aa), UINT32_C(0xd62f105d),
	UINT32_C(0x02441453), UINT32_C(0xd8a1e681), UINT32_C(0xe7d3fbc8),
	UINT32_C(0x21e1cde6), UINT32_C(0xc33707d6), UINT32_C(0xf4d50d87),
	UINT32_C(0x455a14ed), UINT32_C(0xa9e3e905), UINT32_C(0xfcefa3f8),
	UINT32_C(0x676f02d9), UINT32_C(0x8d2a4c8a), UINT32_C(0xfffa3942),
	UINT32_C(0x8771f681), UINT32_C(0x6d9d6122), UINT32_C(0xfde5380c),
	UINT32_C(0xa4beea44), UINT32_C(0x4bdecfa9), UINT32_C(0xf6bb4b60),
	UINT32_C(0xbebfbc70), UINT32_C(0x289b7ec6), UINT32_C(0xeaa127fa),
	UINT32_C(0xd4ef3085), UINT32_C(0x04881d05), UINT32_C(0xd9d4d039),
	UINT32_C(0xe6db99e5), UINT32_C(0x1fa27cf8), UINT32_C(0xc4ac5665),
	UINT32_C(0xf4292244), UINT32_C(0x432aff97), UINT32_C(0xab9423a7),
	UINT32_C(0xfc93a039), UINT32_C(0x655b59c3), UINT32_C(0x8f0ccc92),
	UINT32_C(0xffeff47d), UINT32_C(0x85845dd1), UINT32_C(0x6fa87e4f),
	UINT32_C(0xfe2ce6e0), UINT32_C(0xa3014314), UINT32_C(0x4e0811a1),
	UINT32_C(0xf7537e82), UINT32_C(0xbd3af235), UINT32_C(0x2ad7d2bb),
	UINT32_C(0xeb86d391),
};

static const uint8_t md5_shifts[64] = {
	7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22,
	5,  9,  14, 20, 5,  9,  14, 20, 5,  9,  14, 20, 5,  9,  14, 20,
	4,  11, 16, 23, 4,  11, 16, 23, 4,  11, 16, 23, 4,  11, 16, 23,
	6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21,
};

static uint32_t md5_load32(const uint8_t *bytes) {
	return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
	       (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;
}

static void md5_store32(uint8_t *bytes, uint32_t value) {
	bytes[0] = (uint8_t)value;
	bytes[1] = (uint8_t)(value >> 8);
	bytes[2] = (uint8_t)(value >> 16);
	bytes[3] = (uint8_t)(value >> 24);
}

static uint32_t md5_rotate(uint32_t value, uint8_t shift) {
	return value << shift | value >> (32 - shift);
}

static void md5_transform(struct md5_context *context,
			  const uint8_t block[MD5_BLOCK_SIZE]) {
	uint32_t words[16];
	uint32_t a = context->state[0];
	uint32_t b = context->state[1];
	uint32_t c = context->state[2];
	uint32_t d = context->state[3];
	uint32_t i;

	for (i = 0; i < 16; ++i)
		words[i] = md5_load32(block + i * 4);

	for (i = 0; i < 64; ++i) {
		uint32_t function;
		uint32_t index;
		uint32_t previous_d;

		if (i < 16) {
			function = (b & c) | (~b & d);
			index = i;
		} else if (i < 32) {
			function = (d & b) | (~d & c);
			index = (5 * i + 1) & 15;
		} else if (i < 48) {
			function = b ^ c ^ d;
			index = (3 * i + 5) & 15;
		} else {
			function = c ^ (b | ~d);
			index = 7 * i & 15;
		}

		previous_d = d;
		d = c;
		c = b;
		b += md5_rotate(a + function + md5_constants[i] + words[index],
				md5_shifts[i]);
		a = previous_d;
	}

	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
}

void md5_init(struct md5_context *context) {
	context->state[0] = UINT32_C(0x67452301);
	context->state[1] = UINT32_C(0xefcdab89);
	context->state[2] = UINT32_C(0x98badcfe);
	context->state[3] = UINT32_C(0x10325476);
	context->size = 0;
	context->used = 0;
}

void md5_update(struct md5_context *context, const void *data, size_t size) {
	const uint8_t *bytes = data;

	context->size += size;
	while (size) {
		size_t available = MD5_BLOCK_SIZE - context->used;
		size_t copied = size < available ? size : available;

		memcpy(context->block + context->used, bytes, copied);
		context->used += copied;
		bytes += copied;
		size -= copied;
		if (context->used == MD5_BLOCK_SIZE) {
			md5_transform(context, context->block);
			context->used = 0;
		}
	}
}

void md5_final(struct md5_context *context,
	       uint8_t digest[MD5_DIGEST_SIZE]) {
	uint8_t padding[MD5_BLOCK_SIZE] = {0x80};
	uint8_t length[8];
	uint64_t bits = context->size * 8;
	size_t padding_size;
	uint32_t i;

	for (i = 0; i < 8; ++i)
		length[i] = (uint8_t)(bits >> (i * 8));
	padding_size = context->used < 56 ? 56 - context->used
					  : 120 - context->used;
	md5_update(context, padding, padding_size);
	md5_update(context, length, sizeof(length));
	for (i = 0; i < 4; ++i)
		md5_store32(digest + i * 4, context->state[i]);
}

uint64_t md5_u64(uint64_t input) {
	struct md5_context context;
	uint8_t digest[MD5_DIGEST_SIZE];
	uint8_t message[8];
	uint64_t result = 0;
	uint32_t i;

	for (i = 0; i < 8; ++i)
		message[i] = (uint8_t)(input >> (i * 8));
	md5_init(&context);
	md5_update(&context, message, sizeof(message));
	md5_final(&context, digest);
	for (i = 0; i < 8; ++i)
		result |= (uint64_t)digest[i] << (i * 8);
	return result;
}
