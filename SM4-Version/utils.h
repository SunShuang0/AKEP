#pragma once
/**
 * @brief ���ܺ���
 *
 * @param ��Կ
 * @param ����
 * @param ���ĳ���
 * @param ����
 *
 */
void encrypt(unsigned char * key, unsigned char * plainText, int plainLen, unsigned char * cipherText);

/**
 * @brief ���ܺ���
 *
 * @param ��Կ
 * @param ����
 * @param ���ĳ���
 * @param ����
 *
 */
void decrypt(unsigned char * key, unsigned char * cipherText, int cipherLen, unsigned char * plainText);