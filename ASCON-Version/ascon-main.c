#include <stdio.h>
#include "ascon.h"

int ascon_main() {

	const uint8_t plaintextPtr[] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
									0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
									0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
									0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F };
	const uint8_t associateData[] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
								   0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F };
	const uint8_t key[] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
							0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F };
	uint32_t plaintextLength = 32;
	uint32_t ciphertextLength = 0;
	uint32_t* ciphertextLengthPtr = &ciphertextLength;
	uint32_t associateDataLength = 32;

	uint8_t ciphertextPtr[100];
	uint8_t plaintextPtr2[100];
	uint8_t tag[100];
	uint32_t tagLength = 0;
	uint32_t* tagLengthPtr = &tagLength;
	uint32_t plaintextLength2 = 0;
	uint32_t* plaintextLengthPtr2 = &plaintextLength2;

	int verify = 0;
	int* verifyPtr = &verify;

	encrypt_aead(0, 0,
		plaintextPtr, plaintextLength,
		associateData, associateDataLength,
		ciphertextPtr, ciphertextLengthPtr,
		tag, tagLengthPtr,
		key);

	printf("ciphertext:\n");
	for (int i = 0; i < (*ciphertextLengthPtr); i++) {
		printf("%02X", ciphertextPtr[i]);
	}
	printf("\n");
	printf("tag:\n");
	for (int i = 0; i < (*tagLengthPtr); i++) {
		printf("%02X", tag[i]);
	}
	printf("\n");

	decrypt_aead(0, 0,
		ciphertextPtr, ciphertextLength,
		associateData, associateDataLength,
		tag, tagLength,
		plaintextPtr2, plaintextLengthPtr2,
		verifyPtr,
		key);

	if (!(*verifyPtr)) {
		printf("plaintext:\n");
		for (int i = 0; i < plaintextLength2; i++) {
			printf("%02X", plaintextPtr2[i]);
		}
	}

	return 0;
}
