#pragma once
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