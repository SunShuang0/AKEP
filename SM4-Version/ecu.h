#pragma once
unsigned char C_TNB[3] = { 0x00,0x00,0x00 };
unsigned char TNC[3] = { 0x00,0x00,0x00 };

static unsigned char C_KBC[8] = { 0xbc, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd };
static const unsigned char C_IDB = 0x11;
static const unsigned char IDC = 0x21;
unsigned char SIDC = 0x21;

/**
 * @brief 拼接字符串
 *
 * @param 拼接后的字符数组
 *
 */
void ECU_jointString_DC(unsigned char * ECU_jointedStr_DC);

/**
 * @brief 验证token中的变量
 *
 * @param 从token中解密出的明文字符数组
 *
 */
void ECU_verify_DC(unsigned char * tempPlain);

/**
 * @brief 域内ECU生成对域控制器的token
 *
 * @param token字符数组
 * 
 */
void ECU_genToken_DC(unsigned char * ECU_token_DC);

/**
 * @brief 域内ECU生成对域控制器的会话密钥
 *
 * @param 域控制发来的token
 * @param ECU生成的会话密钥
 * @param 会话密钥长度
 * 
 */
void ECU_genSKey_DC(unsigned char * DC_token_ECU, unsigned char * ECU_sessionKey_DC, int sessionKeyLen);
