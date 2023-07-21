#define _CRT_SECURE_NO_WARNINGS
#define KEY_LENGTH 16
#define BLOCK_LENGTH 16
#define TOKEN_LEN 32
#define SESSION_KEY_LEN 4
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "main.h"

void layerOne()
{
	unsigned char DC_token_GW[TOKEN_LEN] = { 0x00 };
	DC_genToken_GW(DC_token_GW);						// Domain Controller generates token to Gateway
	
	unsigned char GW_token_DC[TOKEN_LEN] = { 0x00 };
	GW_genToken_DC(DC_token_GW, GW_token_DC);			// Gateway generates token to Domain Controller
	
	unsigned char GW_sessionKey_DC[4] = { 0x00 };
	GW_genSKey_DC(GW_sessionKey_DC, SESSION_KEY_LEN);	// Gateway generates session key

	unsigned char DC_sessionKey_GW[4] = { 0x00 };
	DC_genSKey_GW(GW_token_DC, DC_sessionKey_GW, SESSION_KEY_LEN);// Domain Controller generates session key

}

void layerTwo()
{
	unsigned char ECU_token_DC[TOKEN_LEN] = { 0x00 };
	ECU_genToken_DC(ECU_token_DC);						// ECU generates token to Domain Controller
	
	unsigned char DC_token_ECU[TOKEN_LEN] = { 0x00 };
	DC_genToken_ECU(ECU_token_DC, DC_token_ECU);		// Domain Controller generates token to ECU
	
	unsigned char DC_sessionKey_ECU[4] = { 0x00 };
	DC_genSKey_ECU(DC_sessionKey_ECU, SESSION_KEY_LEN);// Domain Controller generates session key

	unsigned char ECU_sessionKey_DC[4] = { 0x00 };
	ECU_genSKey_DC(DC_token_ECU, ECU_sessionKey_DC, SESSION_KEY_LEN);// ECU generates session key
}

int main()
{
	printf("#################### ¡ý Layer One Begin ¡ý ####################\n\n");
	printf("Session Key between gateway and controller\n\n");
	layerOne();

	printf("\n\n#################### ¡ý Layer Two Begin ¡ý ####################\n\n");
	printf("Session Key between controller and ECU\n\n");
	layerTwo();
}

