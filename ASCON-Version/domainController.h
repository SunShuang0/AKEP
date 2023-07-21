#pragma once
unsigned char B_TNA[3] = { 0x00,0x00,0x00 };
unsigned char TNB[3] = { 0x00,0x00,0x00 };
unsigned char B_TNC[3] = { 0x00,0x00,0x00 };

static unsigned char B_KGB[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
static unsigned char B_KAB[8] = { 0xab, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd };
static unsigned char B_KBC[8] = { 0xbc, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd };
unsigned char FB[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
unsigned char B_FA[8] = { 0x00 };

static const unsigned char B_IDA = 0x01;
static const unsigned char IDB = 0x11;
static const unsigned char B_IDC = 0x21;
unsigned char SIDB = 0x11;
unsigned char SIDBC = 0x22;
unsigned char B_SIDC = 0x00;

/**
 * @brief ƴ���ַ���
 *
 * @param ƴ�Ӻ���ַ�����
 *
 */
void DC_jointString_GW(unsigned char * DC_jointedStr_GW);

/**
 * @brief ��֤���ط�����token�еı���
 *
 * @param ��token�н��ܳ��������ַ�����
 *
 */
void DC_verify_GW(unsigned char * tempPlain);

/**
 * @brief ���ECU������token
 *
 * @param ECU������token
 * @param token�е����ĳ���
 * @param ��token�в���������
 * 
 */
void DC_parseToken_ECU(unsigned char * ECU_token_DC, int cipherLength, unsigned char * tempCipher);

/**
 * @brief ��֤ECU������token�еı���
 *
 * @param ��token�н��ܳ��������ַ�����
 *
 */
void DC_verify_ECU(unsigned char * tempPlain);

/**
 * @brief ƴ���ַ���
 *
 * @param ƴ�Ӻ���ַ�����
 *
 */
void DC_jointString_ECU(unsigned char * DC_jointedStr_ECU);

/**
 * @brief ����������ɶ����ص�token
 *
 * @param token�ַ�����
 *
 */
void DC_genToken_GW(unsigned char * DC_token_GW);

/**
 * @brief ����������ɶ����صĻỰ��Կ
 *
 * @param ���ط�����token
 * @param ����ECU���ɵĻỰ��Կ
 * @param �Ự��Կ����
 *
 */
void DC_genSKey_GW(unsigned char * GW_token_DC, unsigned char * DC_sessionKey_GW, int sessionKeyLen);

/**
 * @brief ����������ɶ�����ECU��token
 *
 * @param ECU������token
 * @param ����������ɵ�token�ַ�����
 *
 */
void DC_genToken_ECU(unsigned char * ECU_token_DC, unsigned char * DC_token_ECU);

/**
 * @brief ����������ɶ�����ECU�ĻỰ��Կ
 *
 * @param ����������ɵĻỰ��Կ
 * @param �Ự��Կ����
 *
 */
void DC_genSKey_ECU(unsigned char * DC_sessionKey_ECU, int sessionKeyLen);