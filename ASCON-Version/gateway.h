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
 * @brief 拼接字符串
 *
 * @param 拼接后的字符数组
 *
 */
void GW_jointString_DC(unsigned char * GW_jointedStr_DC);

/**
 * @brief 验证token中的变量
 *
 * @param 从token中解密出的明文字符数组
 *
 */
void GW_verify_DC(unsigned char * tempPlain);

/**
 * @brief 拆解域控制器发来的token
 *
 * @param 域控制器发来的token
 * @param token中的密文长度
 * @param 从token中拆解出的密文
 *
 */
void GW_parseToken_DC(unsigned char * DC_token_GW, int cipherLength, unsigned char * tempCipher);

/**
 * @brief 网关生成对域控制器的token
 *
 * @param token字符数组
 *
 */
void GW_genToken_DC(unsigned char * DC_token_GW, unsigned char * GW_token_DC);

/**
 * @brief 网关生成对域控制器的会话密钥
 *
 * @param 网关生成的会话密钥
 * @param 会话密钥长度
 *
 */
void GW_genSKey_DC(unsigned char * GW_sessionKey_DC, int sessionKeyLen);