#include <stdint.h>
#include "utils.h"

void encrypt(unsigned char * key, unsigned char * plainText, int plainLen, unsigned char * cipherText)
{
	uint8_t encryptKey[16] = { 0x00 };
	for (int i = 0; i < 8; i++)
	{
		encryptKey[i] = key[i];
	}

	encrypt_aead(0, 0,
		plainText, plainLen,
		associateData, associateDataLength,
		cipherText, ciphertextLengthPtr,
		tag, tagLengthPtr,
		encryptKey);
}

void decrypt(unsigned char * key, unsigned char * cipherText, int cipherLen, unsigned char * plainText)
{
	uint8_t encryptKey[16] = { 0x00 };
	for (int i = 0; i < 8; i++)
	{
		encryptKey[i] = key[i];
	}

	decrypt_aead(0, 0,
		cipherText, 32,
		associateData, associateDataLength,
		tag, tagLength,
		plainText, plaintextLengthPtr2,
		verifyPtr,
		encryptKey);
}

///////////////////	V3.0 SM4¼ÓÃÜ°æ	//////////////////////
//void encrypt(unsigned char * key, unsigned char * plainText, int plainLen, unsigned char * cipherText)
//{
//	unsigned char encryptKey[16] = { 0x00 };
//	for (int i = 0; i < 8; i++)
//	{
//		encryptKey[i] = key[i];
//	}
//
//	int num = plainLen / 16;
//	if (plainLen % 16 != 0)
//	{
//		num += 1;
//	}
//	for (int i = 0; i < num; i++)
//	{
//		unsigned char tempBlock[16] = { 0x00 };
//		for (int j = 0; j < 16; j++)
//		{
//			tempBlock[j] = plainText[i * 16 + j];
//		}
//
//		unsigned char tempCipher[16] = { 0x00 };
//		SM4_Encrypt(encryptKey, tempBlock, tempCipher);
//		for (int j = 0; j < 16; j++)
//		{
//			cipherText[i * 16 + j] = tempCipher[j];
//		}
//	}
//}
//
//void decrypt(unsigned char * key, unsigned char * cipherText, int cipherLen, unsigned char * plainText)
//{
//	unsigned char decryptKey[16] = { 0x00 };
//	for (int i = 0; i < 8; i++)
//	{
//		decryptKey[i] = key[i];
//	}
//
//	int num = cipherLen / 16;
//	if (cipherLen % 16 != 0)
//	{
//		num += 1;
//	}
//	for (int i = 0; i < num; i++)
//	{
//		unsigned char tempCipher[16] = { 0x00 };
//		for (int j = 0; j < 16; j++)
//		{
//			tempCipher[j] = cipherText[i * 16 + j];
//		}
//
//		unsigned char tempPlain[16] = { 0x00 };
//		SM4_Decrypt(decryptKey, tempCipher, tempPlain);
//		for (int j = 0; j < 16; j++)
//		{
//			plainText[i * 16 + j] = tempPlain[j];
//		}
//	}
//}
