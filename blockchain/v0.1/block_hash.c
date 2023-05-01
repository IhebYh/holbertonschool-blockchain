#include "blockchain.h"

/**
 * block_hash - computes hash of block
 * @block: pointer to block to hash
 * @hash_buf: buffer to store hash/digest
 * Return: pointer to buffer
 */
uint8_t *block_hash(block_t const *block,
					uint8_t hash_buf[SHA256_DIGEST_LENGTH])
{
	if (!block || !hash_buf)
		return (NULL);

	size_t len = sizeof(block->info) + block->data.len;

	return(sha256((int8_t const *)&(block->info), len, hash_buf))
}
