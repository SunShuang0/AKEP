#pragma once
#ifndef ASCON_1_ASCON_H
#define ASCON_1_ASCON_H
#include <stdint.h>

int encrypt_aead(uint32_t jobId, int mode,
	const uint8_t* plaintextPtr, uint32_t plaintextLength,
	const uint8_t* associatedDataPtr, uint32_t associatedDataLength,
	uint8_t* ciphertextPtr, uint32_t* ciphertextLengthPtr,
	uint8_t* tagPtr, uint32_t* tagLengthPtr,
	const uint8_t* key);


int decrypt_aead(uint32_t jobId, int mode,
	const uint8_t* ciphertextPtr, uint32_t ciphertextLength,
	const uint8_t* associatedDataPtr, uint32_t associatedDataLength,
	const uint8_t* tagPtr, uint32_t tagLengthPtr,
	uint8_t* plaintextPtr, uint32_t* plaintextLengthPtr,
	int* verifyPtr,
	const uint8_t* key);



#endif //ASCON_1_ASCON_H

