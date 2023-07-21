#include "domainController.h"
#include <stdint.h>

/**
 * 拼接字符串
 */
void DC_jointString_GW(unsigned char * DC_jointedStr_GW)
{
	int i = 1;
	DC_jointedStr_GW[0] = SIDB;

	TNB[2] += 1;				// TNB+1 first, then joint
	for (int j = 0; j < 3; j++)
	{
		DC_jointedStr_GW[i] = TNB[j];
		i++;
	}

	DC_jointedStr_GW[i] = B_IDA;

	for (int t = 0; t < 8; t++)
	{
		i++;
		DC_jointedStr_GW[i] = FB[t];
	}
}

/**
 * 验证网关发来的token中的变量
 */
void DC_verify_GW(unsigned char * tempPlain)
{
	int i = 1;
	unsigned char de_TNA[3];
	unsigned char de_TNB[3];
	unsigned char a = 0, b = 0, c = 0, d = 0;
	for (int j = 0; j < 3; j++)
	{
		de_TNA[j] = tempPlain[i];
		de_TNB[j] = tempPlain[i + 3];
		a += de_TNA[j];
		b += de_TNB[j];
		c += B_TNA[j];
		d += TNB[j];
		i++;
	}

	i += 3;
	unsigned char de_IDB = tempPlain[i];

	// de_TNA should greater than local TNA, de_TNB should equal local TNB
	if ( (a - c <= 0) || (b != d) || de_IDB != IDB)
	{
		printf("ERROR! Domain Controller Identify Gateway Failed!\n");
		return 1;
	}
	else
	{
		for (int j = 0; j < 3; j++)
		{
			B_TNA[j] = de_TNA[j];	// update local TNA
		}
	}

	for (int t = 0; t < 8; t++)
	{
		i++;
		B_FA[t] = tempPlain[i];
	}
}

/**
 * 拆解ECU发来的token
 */
void DC_parseToken_ECU(unsigned char * ECU_token_DC, int cipherLength, unsigned char * tempCipher)
{
	for (int i = 0; i < cipherLength; i++)
	{
		tempCipher[i] = ECU_token_DC[i];
	}
}

/**
 * 验证ECU发来的token中的变量
 */
void DC_verify_ECU(unsigned char * tempPlain)
{
	B_SIDC = tempPlain[0];
	int i = 0;
	unsigned char de_TNC[3];
	unsigned char a = 0, b = 0;
	for (int j = 0; j < 3; j++)
	{
		i++;
		de_TNC[j] = tempPlain[j + 1];
		a += de_TNC[j];
		b += B_TNC[j];
	}
	
	unsigned char de_IDB = tempPlain[++i];

	if ((a - b <= 0) || de_IDB != IDB)
	{
		printf("ERROR! Domain Controller Identify ECU Failed!\n");
		return 1;
	}

	for (int i = 0; i < 3; i++)
	{
		B_TNC[i] = de_TNC[i];		// update local TNC
	}
}

/**
 * 拼接对ECU的字符串
 */
void DC_jointString_ECU(unsigned char * DC_jointedStr_ECU)
{
	TNB[2] += 1;	// TNB + 1 first, then joint

	DC_jointedStr_ECU[0] = SIDB;

	int i = 1;
	for (int j = 0; j < 3; j++)
	{
		DC_jointedStr_ECU[i] = TNB[j];
		DC_jointedStr_ECU[i + 3] = B_TNC[j];
		i++;
	}

	i += 3;
	DC_jointedStr_ECU[i] = B_IDC;

	for (int t = 0; t < 8; t++)
	{
		i++;
		DC_jointedStr_ECU[i] = B_KGB[t];
	}
}

/**
 * 域控制器生成对网关的token
 */
void DC_genToken_GW(unsigned char * DC_token_GW)
{
	unsigned char DC_jointedStr_GW[32] = { 0x00 };
	DC_jointString_GW(DC_jointedStr_GW);		// joints string for next encryption

	unsigned char DC_cipher_GW[32] = { 0x00 };	// encrypts the string
	encrypt(B_KAB, DC_jointedStr_GW, 32, DC_cipher_GW);

	for (int j = 0; j < 32; j++)				// generates token to Gateway
	{
		DC_token_GW[j] = DC_cipher_GW[j];
	}
	DC_token_GW[32] = IDB;

}

/**
 * 域控制器生成对网关的会话密钥
 */
void DC_genSKey_GW(unsigned char * GW_token_DC, unsigned char * DC_sessionKey_GW, int sessionKeyLen)
{
	unsigned char plainText[32] = { 0x00 };

	decrypt(B_KAB, GW_token_DC, 32, plainText);	// decrypts token from Gateway
	
	DC_verify_GW(plainText);					// verifies variables from token

	unsigned char originalStr[32] = { 0x00 };	// joints a new string for session key generate
	int m = 0;
	for (m; m < 8; m++)
	{
		originalStr[m] = B_FA[m];
	}
	for (m; m < 16; m++)
	{
		originalStr[m] = FB[m - 8];
	}
	for (m; m < 19; m++)
	{
		originalStr[m] = B_TNA[m - 16];
	}
	for (m; m < 22; m++)
	{
		originalStr[m] = TNB[m - 19];
	}

	originalStr[m] = B_IDA;
	originalStr[m + 1] = IDB;
	originalStr[m + 2] = SIDB;

	// call to sessKDF()
	int originalStrLen = 32;
	sessKDF(originalStr, originalStrLen, sessionKeyLen, DC_sessionKey_GW);
	printf("DC_sessionKey_GW: %x%x%x%x\n", DC_sessionKey_GW[0], DC_sessionKey_GW[1], DC_sessionKey_GW[2], DC_sessionKey_GW[3]);
}

/**
 * 域控制器生成对域内ECU的token
 */
void DC_genToken_ECU(unsigned char * ECU_token_DC, unsigned char * DC_token_ECU)
{
	unsigned char tempPlain[32] = { 0x00 };
	unsigned char tempCipher[32] = { 0x00 };
	
	DC_parseToken_ECU(ECU_token_DC, 32, tempCipher);// parses token, takes out cipher text

	decrypt(B_KBC, tempCipher, 32, tempPlain);		// decrypts cipher text from token

	DC_verify_ECU(tempPlain);						// verifies variables from decrypted token string

	unsigned char DC_jointedStr_ECU[32] = { 0x00 };
	DC_jointString_ECU(DC_jointedStr_ECU);			// joints a new string for next encryption

	encrypt(B_KBC, DC_jointedStr_ECU, 32, DC_token_ECU);	// encrypts the string
}

/**
 * 域控制器生成对域内ECU的会话密钥
 */
void DC_genSKey_ECU(unsigned char * DC_sessionKey_ECU, int sessionKeyLen)
{
	unsigned char originalStr[16] = { 0x00 };
	int m = 0;
	for (m; m < 3; m++)
	{
		originalStr[m] = TNB[m];
	}
	for (m; m < 6; m++)
	{
		originalStr[m] = B_TNC[m - 3];
	}
	originalStr[m] = IDB;//m=6;
	originalStr[m + 1] = B_IDC;
	originalStr[m + 2] = B_SIDC;

	// call to sessKDF()
	int originalStrLen = 16;
	sessKDF(originalStr, originalStrLen, sessionKeyLen, DC_sessionKey_ECU);
	printf("DC_sessionKey_ECU: %x%x%x%x\n", DC_sessionKey_ECU[0], DC_sessionKey_ECU[1], DC_sessionKey_ECU[2], DC_sessionKey_ECU[3]);
}