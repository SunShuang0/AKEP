#include "ascon.h"
#include "def.h"

int encrypt_aead(uint32_t jobId, int mode,
	const uint8_t* plaintextPtr, uint32_t plaintextLength,
	const uint8_t* associatedDataPtr, uint32_t associatedDataLength,
	uint8_t* ciphertextPtr, uint32_t* ciphertextLengthPtr,
	uint8_t* tagPtr, uint32_t* tagLengthPtr,
	const uint8_t* key) {

	/* set a constant nonce value in ascon */
	const unsigned char npub[] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F };


	/* set ciphertext size */
	*ciphertextLengthPtr = plaintextLength;

	/* load key and nonce */
	const uint64_t K0 = LOADBYTES(key, 8);
	const uint64_t K1 = LOADBYTES(key + 8, 8);
	const uint64_t N0 = LOADBYTES(npub, 8);
	const uint64_t N1 = LOADBYTES(npub + 8, 8);

	/* initialize */
	state_t s;
	s.x[0] = ASCON_128_IV;
	s.x[1] = K0;
	s.x[2] = K1;
	s.x[3] = N0;
	s.x[4] = N1;

	P12(&s);
	s.x[3] ^= K0;
	s.x[4] ^= K1;


	if (associatedDataLength) {
		/* full associated data blocks */
		while (associatedDataLength >= ASCON_128_RATE) {
			s.x[0] ^= LOADBYTES(associatedDataPtr, 8);

			P6(&s);
			associatedDataPtr += ASCON_128_RATE;
			associatedDataLength -= ASCON_128_RATE;
		}
		/* final associated data block */
		s.x[0] ^= LOADBYTES(associatedDataPtr, associatedDataLength);
		s.x[0] ^= PAD(associatedDataLength);
		P6(&s);
	}


	/* domain separation */
	s.x[4] ^= 1;


	/* full plaintext blocks */
	while (plaintextLength >= ASCON_128_RATE) {
		s.x[0] ^= LOADBYTES(plaintextPtr, 8);
		STOREBYTES(ciphertextPtr, s.x[0], 8);

		P6(&s);
		plaintextPtr += ASCON_128_RATE;
		ciphertextPtr += ASCON_128_RATE;
		plaintextLength -= ASCON_128_RATE;
	}
	/* final plaintext block */
	s.x[0] ^= LOADBYTES(plaintextPtr, plaintextLength);
	STOREBYTES(ciphertextPtr, s.x[0], plaintextLength);
	s.x[0] ^= PAD(plaintextLength);


	/* finalize */
	s.x[1] ^= K0;
	s.x[2] ^= K1;

	P12(&s);
	s.x[3] ^= K0;
	s.x[4] ^= K1;


	/* set tag */
	*tagLengthPtr = CRYPTO_ABYTES;
	STOREBYTES(tagPtr, s.x[3], 8);
	STOREBYTES(tagPtr + 8, s.x[4], 8);

	return 0;
}



int decrypt_aead(uint32_t jobId, int mode,
	const uint8_t* ciphertextPtr, uint32_t ciphertextLength,
	const uint8_t* associatedDataPtr, uint32_t associatedDataLength,
	const uint8_t* tagPtr, uint32_t tagLengthPtr,
	uint8_t* plaintextPtr, uint32_t* plaintextLengthPtr,
	int* verifyPtr,
	const uint8_t* key) {

	/* set a constant nonce value in ascon */
	const unsigned char npub[] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F };

	/* set plaintext size */
	*plaintextLengthPtr = ciphertextLength;

	/* load key and nonce */
	const uint64_t K0 = LOADBYTES(key, 8);
	const uint64_t K1 = LOADBYTES(key + 8, 8);
	const uint64_t N0 = LOADBYTES(npub, 8);
	const uint64_t N1 = LOADBYTES(npub + 8, 8);

	/* initialize */
	state_t s;
	s.x[0] = ASCON_128_IV;
	s.x[1] = K0;
	s.x[2] = K1;
	s.x[3] = N0;
	s.x[4] = N1;

	P12(&s);
	s.x[3] ^= K0;
	s.x[4] ^= K1;


	if (associatedDataLength) {
		/* full associated data blocks */
		while (associatedDataLength >= ASCON_128_RATE) {
			s.x[0] ^= LOADBYTES(associatedDataPtr, 8);

			P6(&s);
			associatedDataPtr += ASCON_128_RATE;
			associatedDataLength -= ASCON_128_RATE;
		}
		/* final associated data block */
		s.x[0] ^= LOADBYTES(associatedDataPtr, associatedDataLength);
		s.x[0] ^= PAD(associatedDataLength);
		P6(&s);
	}


	/* domain separation */
	s.x[4] ^= 1;

	/* full ciphertext blocks */
	while (ciphertextLength >= ASCON_128_RATE) {
		uint64_t c0 = LOADBYTES(ciphertextPtr, 8);
		STOREBYTES(plaintextPtr, s.x[0] ^ c0, 8);
		s.x[0] = c0;

		P6(&s);
		plaintextPtr += ASCON_128_RATE;
		ciphertextPtr += ASCON_128_RATE;
		ciphertextLength -= ASCON_128_RATE;
	}
	/* final ciphertext block */
	uint64_t c0 = LOADBYTES(ciphertextPtr, ciphertextLength);
	STOREBYTES(plaintextPtr, s.x[0] ^ c0, ciphertextLength);
	s.x[0] = CLEARBYTES(s.x[0], ciphertextLength);
	s.x[0] |= c0;
	s.x[0] ^= PAD(ciphertextLength);


	/* finalize */
	s.x[1] ^= K0;
	s.x[2] ^= K1;

	P12(&s);
	s.x[3] ^= K0;
	s.x[4] ^= K1;


	/* set tag */
	uint8_t t[16];
	STOREBYTES(t, s.x[3], 8);
	STOREBYTES(t + 8, s.x[4], 8);

	/* verify tag (should be constant time, check compiler output) */
	int result = 0;
	for (int i = 0; i < CRYPTO_ABYTES; ++i) result |= tagPtr[i] ^ t[i];
	result = (((result - 1) >> 8) & 1) - 1;

	*verifyPtr = result;

	return result;
}
