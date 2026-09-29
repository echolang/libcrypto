/*
 * What Echo can't say to Monocypher directly.
 *
 * crypto_argon2 takes three structs by value, which is ABI Echo shouldn't
 * have to get right, and wants a caller-owned work area of nb_blocks KiB.
 * The incremental BLAKE2b needs a context whose layout Monocypher reserves
 * the right to change, so it lives on the C heap behind an opaque pointer.
 * And crypto_ed25519_key_pair wipes the seed it is given, which Echo's
 * copy-on-write strings have no business being written into.
 */

#include <stdlib.h>
#include <string.h>
#include "monocypher.h"
#include "monocypher-ed25519.h"

int libcrypto_argon2id(uint8_t *hash, uint32_t hash_size,
                       const uint8_t *pass, uint32_t pass_size,
                       const uint8_t *salt, uint32_t salt_size,
                       uint32_t nb_blocks, uint32_t nb_passes,
                       uint32_t nb_lanes)
{
	void *work = malloc((size_t)nb_blocks * 1024);

	if (work == NULL) {
		return -1;
	}

	crypto_argon2_config config = {
		.algorithm = CRYPTO_ARGON2_ID,
		.nb_blocks = nb_blocks,
		.nb_passes = nb_passes,
		.nb_lanes  = nb_lanes,
	};
	crypto_argon2_inputs inputs = {
		.pass      = pass,
		.salt      = salt,
		.pass_size = pass_size,
		.salt_size = salt_size,
	};

	// crypto_argon2 zeroes the work area itself before returning
	crypto_argon2(hash, hash_size, work, config, inputs, crypto_argon2_no_extras);
	free(work);
	return 0;
}

crypto_blake2b_ctx *libcrypto_blake2b_new(size_t hash_size,
                                          const uint8_t *key, size_t key_size)
{
	crypto_blake2b_ctx *ctx = malloc(sizeof *ctx);

	if (ctx != NULL) {
		crypto_blake2b_keyed_init(ctx, hash_size, key, key_size);
	}

	return ctx;
}

void libcrypto_blake2b_free(crypto_blake2b_ctx *ctx)
{
	crypto_wipe(ctx, sizeof *ctx);
	free(ctx);
}

void libcrypto_ed25519_key_pair(uint8_t secret_key[64], uint8_t public_key[32],
                                const uint8_t seed[32])
{
	uint8_t scratch[32];

	memcpy(scratch, seed, 32);
	crypto_ed25519_key_pair(secret_key, public_key, scratch);
}
