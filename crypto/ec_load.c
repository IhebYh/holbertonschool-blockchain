#include "hblk_crypto.h"

/**
 * ec_load - loads public/private keys in PEM format
 * @folder: the folder to save, created if need be
 * Return: EC_KEY on success else NULL
 */
EC_KEY *ec_load(char const *folder)
{
	FILE *fp;
	char path[128] = {0};
	EC_KEY *key = NULL;

	if (!folder)
		return (0);

	sprintf(path, "%s/" PUB_FILENAME, folder);
	fp = fopen(path, "r");
	if (!fp)
	{
		EC_KEY_free(key);
		return (0);
	}
	if (!PEM_read_EC_PUBKEY(fp, &key, NULL, NULL))
	{
		EC_KEY_free(key);
		fclose(fp);
		return (0);
	}
	fclose(fp);

	sprintf(path, "%s/" PRI_FILENAME, folder);
	fp = fopen(path, "r");
	if (!fp)
		return (0);
	if (!PEM_read_ECPrivateKey(fp, &key, NULL, NULL))
	{
		fclose(fp);
		return (0);
	}
	fclose(fp);
	return (key);
}
