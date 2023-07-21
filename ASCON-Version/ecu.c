#include "ecu.h"

/**
 * ƴ���ַ���
 */
void ECU_jointString_DC(unsigned char * ECU_jointedStr_DC)
{
	int i = 1;

	ECU_jointedStr_DC[0] = SIDC;

	TNC[2] += 1;						// TNC+1 first, then joint
	for (int j = 0; j < 3; j++)
	{
		ECU_jointedStr_DC[i] = TNC[j];
		i++;
	}

	ECU_jointedStr_DC[i] = C_IDB;
}

/**
 * ��֤token�еı���
 */
void ECU_verify_DC(unsigned char * tempPlain)
{
	// take out TNB, TNC, IDC
	int i = 1;
	unsigned char de_TNB[3];
	unsigned char de_TNC[3];
	unsigned char a = 0, b = 0, c = 0, d = 0;
	for (int j = 0; j < 3; j++)
	{
		de_TNB[j] = tempPlain[i];
		de_TNC[j] = tempPlain[i + 3];
		a += de_TNB[j];
		b += de_TNC[j];
		c += C_TNB[j];
		d += TNC[j];
		i++;
	}

	i += 3;
	unsigned char de_IDC = tempPlain[i];

	// de_TNB should greater than local TNB, de_TNC should equal local TNC
	if ((a - c <= 0) || (b != d) || de_IDC != IDC)
	{
		printf("ERROR! ECU Identify Domain Controller Failed!\n");
		return 1;
	}
	else
	{
		for (int j = 0; j < 3; j++)
		{
			C_TNB[j] = de_TNB[j];	// update local TNB
		}
	}
}

/**
 * ����ECU���ɶ����������token
 */
void ECU_genToken_DC(unsigned char * ECU_token_DC)
{	
	unsigned char ECU_jointedStr_GW[32] = { 0x00 };
	ECU_jointString_DC(ECU_jointedStr_GW);	// ECU joints string for encryption
	
	unsigned char ECU_cipher_DC[32] = { 0x00 };
	encrypt(C_KBC, ECU_jointedStr_GW, 32, ECU_cipher_DC);	// ECU encrypts the string

	for (int j = 0; j < 32; j++)	// ECU generates token to Domain Controller
	{
		ECU_token_DC[j] = ECU_cipher_DC[j];
	}
	ECU_token_DC[32] = IDC;
}

/**
 * ����ECU���ɶ���������ĻỰ��Կ
 */
void ECU_genSKey_DC(unsigned char * DC_token_ECU, unsigned char * ECU_sessionKey_DC, int sessionKeyLen)
{
	unsigned char plainText[32] = { 0x00 };
	unsigned char tokenCipher[32] = { 0x00 };

	decrypt(C_KBC, DC_token_ECU, 32, plainText);	// ECU decrypts token from Gateway

	ECU_verify_DC(plainText);	// ECU verifies variables from token

	unsigned char originalStr[16] = { 0x00 };

	// originalStr = TNB || TNC || IDB || IDC || SIDC
	int m = 0;
	for (m; m < 3; m++)
	{
		originalStr[m] = C_TNB[m];
	}
	for (m; m < 6; m++)
	{
		originalStr[m] = TNC[m - 3];
	}

	originalStr[m] = C_IDB;
	originalStr[m + 1] = IDC;
	originalStr[m + 2] = SIDC;

	// call to sessKDF()
	int originalStrLen = 16;
	sessKDF(originalStr, originalStrLen, sessionKeyLen, ECU_sessionKey_DC);
	printf("ECU_sessionKey_DC: %x%x%x%x\n", ECU_sessionKey_DC[0], ECU_sessionKey_DC[1], ECU_sessionKey_DC[2], ECU_sessionKey_DC[3]);
}