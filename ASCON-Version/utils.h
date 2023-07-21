#pragma once
const uint8_t associateData[] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
								0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
								0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
								0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F };
uint32_t plaintextLength = 32;
uint32_t ciphertextLength = 0;
uint32_t* ciphertextLengthPtr = &ciphertextLength;
uint32_t associateDataLength = 32;

uint8_t plaintextPtr2[100];
uint8_t tag[100];
uint32_t tagLength = 0;
uint32_t* tagLengthPtr = &tagLength;
uint32_t plaintextLength2 = 0;
uint32_t* plaintextLengthPtr2 = &plaintextLength2;

int verify = 0;
int* verifyPtr = &verify;
/**
 * @brief 加密函数
 *
 * @param 密钥
 * @param 明文
 * @param 明文长度
 * @param 密文
 *
 */
void encrypt(unsigned char * key, unsigned char * plainText, int plainLen, unsigned char * cipherText);

/**
 * @brief 解密函数
 *
 * @param 密钥
 * @param 密文
 * @param 密文长度
 * @param 明文
 *
 */
void decrypt(unsigned char * key, unsigned char * cipherText, int cipherLen, unsigned char * plainText);