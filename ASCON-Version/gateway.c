#include "gateway.h"

/**
 * @brief 拼接字符串
 */
void GW_jointString_DC(unsigned char * GW_jointedStr_DC)
{	
	TNA[2] += 1;			// TNA + 1 before joint

	GW_jointedStr_DC[0] = SIDA;

	int i = 1;
	for (int j = 0; j < 3; j++)
	{
		GW_jointedStr_DC[i] = TNA[j];
		GW_jointedStr_DC[i + 3] = A_TNB[j];
		i++;
	}

	i += 3;
	GW_jointedStr_DC[i] = A_IDB;

	for (int t = 0; t < 8; t++)
	{
		i++;
		GW_jointedStr_DC[i] = FA[t];
	}

	for (int t = 0; t < 8; t++)
	{
		i++;
		GW_jointedStr_DC[i] = A_KGB[t];
	}

}

/**
 * 验证token中的变量
 */
void GW_verify_DC(unsigned char * tempPlain)
{
	int i = 0;
	unsigned char de_TNB[3];
	unsigned char a = 0, b = 0;
	for (int j = 0; j < 3; j++)
	{
		i++;
		de_TNB[j] = tempPlain[j + 1];
		a += de_TNB[j];
		b += A_TNB[j];
	}

	unsigned char de_IDA = tempPlain[++i]; //i=5
	if ((a - b <= 0) || de_IDA != IDA)
	{
		printf("ERROR! Identify Domain Controller Failed!\n");
		return 1;
	}

	for (int j = 0; j < 3; j++)		// update A_TNB to ensure A_TNB == TNB
	{
		A_TNB[j] = de_TNB[j];
	}

	A_SIDB = tempPlain[0];
	for (int t = 0; t < 8; t++)
	{
		A_FB[t] = tempPlain[i + 1 + t];
	}

}

/**
 * 拆解域控制器发来的token
 */
void GW_parseToken_DC(unsigned char * DC_token_GW, int cipherLength, unsigned char * tempCipher)
{
	for (int i = 0; i < cipherLength; i++)
	{
		tempCipher[i] = DC_token_GW[i];
	}
}

/**
 * 网关生成对域控制器的token
 */
void GW_genToken_DC(unsigned char * DC_token_GW, unsigned char * GW_token_DC)
{
	unsigned char plainText[32] = { 0x00 };
	unsigned char tokenCipher[32] = { 0x00 };
	
	GW_parseToken_DC(DC_token_GW, 32, tokenCipher);		// parses the token from Domain Controller
		
	decrypt(A_KAB, tokenCipher, 32, plainText);			// decrypts encrypted string in token
		
	GW_verify_DC(plainText);							// verifies variables from token

	unsigned char GW_jointedStr_DC[32] = { 0x00 };
	GW_jointString_DC(GW_jointedStr_DC);				// joints new string

	encrypt(A_KAB, GW_jointedStr_DC, 32, GW_token_DC);	// encrypts the string then send to Domain Controller as token
}

/**
 * 网关生成对域控制器的会话密钥
 */
void GW_genSKey_DC(unsigned char * GW_sessionKey_DC, int sessionKeyLen)
{
	unsigned char originalStr[32] = { 0x00 };

	int m = 0;
	for (m; m < 8; m++)
	{
		originalStr[m] = FA[m];
	}
	for (m; m < 16; m++)
	{
		originalStr[m] = A_FB[m - 8];
	}
	for (m; m < 19; m++)
	{
		originalStr[m] = TNA[m - 16];
	}
	for (m; m < 22; m++)
	{
		originalStr[m] = A_TNB[m - 19];
	}

	originalStr[m] = IDA;
	originalStr[m + 1] = A_IDB;
	originalStr[m + 2] = A_SIDB;

	// call to sessKDF()
	int originalStrLen = 32;
	sessKDF(originalStr, originalStrLen, sessionKeyLen, GW_sessionKey_DC);
	printf("GW_sessionKey_DC: %x%x%x%x\n", GW_sessionKey_DC[0], GW_sessionKey_DC[1], GW_sessionKey_DC[2], GW_sessionKey_DC[3]);

}
