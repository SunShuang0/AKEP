#pragma once
unsigned char C_TNB[3] = { 0x00,0x00,0x00 };
unsigned char TNC[3] = { 0x00,0x00,0x00 };

static unsigned char C_KBC[8] = { 0xbc, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd };
static const unsigned char C_IDB = 0x11;
static const unsigned char IDC = 0x21;
unsigned char SIDC = 0x21;

/**
 * @brief ƴ���ַ���
 *
 * @param ƴ�Ӻ���ַ�����
 *
 */
void ECU_jointString_DC(unsigned char * ECU_jointedStr_DC);

/**
 * @brief ��֤token�еı���
 *
 * @param ��token�н��ܳ��������ַ�����
 *
 */
void ECU_verify_DC(unsigned char * tempPlain);

/**
 * @brief ����ECU���ɶ����������token
 *
 * @param token�ַ�����
 * 
 */
void ECU_genToken_DC(unsigned char * ECU_token_DC);

/**
 * @brief ����ECU���ɶ���������ĻỰ��Կ
 *
 * @param ����Ʒ�����token
 * @param ECU���ɵĻỰ��Կ
 * @param �Ự��Կ����
 * 
 */
void ECU_genSKey_DC(unsigned char * DC_token_ECU, unsigned char * ECU_sessionKey_DC, int sessionKeyLen);
