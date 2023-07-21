#pragma once
unsigned char TNA[3] = { 0x00,0x00,0x00 };
unsigned char A_TNB[3] = { 0x00,0x00,0x00 };

static unsigned char A_KGB[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
static unsigned char A_KAB[8] = { 0xab, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd };
unsigned char FA[8] = { 0x11, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
unsigned char A_FB[8] = { 0x00 };

static const unsigned char IDA = 0x01;
static const unsigned char A_IDB = 0x11;
unsigned char SIDA = 0x12;
unsigned char A_SIDB;

/**
 * @brief ƴ���ַ���
 *
 * @param ƴ�Ӻ���ַ�����
 *
 */
void GW_jointString_DC(unsigned char * GW_jointedStr_DC);

/**
 * @brief ��֤token�еı���
 *
 * @param ��token�н��ܳ��������ַ�����
 *
 */
void GW_verify_DC(unsigned char * tempPlain);

/**
 * @brief ����������������token
 *
 * @param �������������token
 * @param token�е����ĳ���
 * @param ��token�в���������
 *
 */
void GW_parseToken_DC(unsigned char * DC_token_GW, int cipherLength, unsigned char * tempCipher);

/**
 * @brief �������ɶ����������token
 *
 * @param token�ַ�����
 *
 */
void GW_genToken_DC(unsigned char * DC_token_GW, unsigned char * GW_token_DC);

/**
 * @brief �������ɶ���������ĻỰ��Կ
 *
 * @param �������ɵĻỰ��Կ
 * @param �Ự��Կ����
 *
 */
void GW_genSKey_DC(unsigned char * GW_sessionKey_DC, int sessionKeyLen);