#pragma once
#ifndef ASCON_1_DEF_H
#define ASCON_1_DEF_H

#define CRYPTO_ABYTES 16
#define ASCON_128_KEYBYTES 16
#define ASCON_128_RATE 8
#define ASCON_128_PA_ROUNDS 12
#define ASCON_128_PB_ROUNDS 6
#define ASCON_128_IV                            \
  (((uint64_t)(ASCON_128_KEYBYTES * 8) << 56) | \
   ((uint64_t)(ASCON_128_RATE * 8) << 48) |     \
   ((uint64_t)(ASCON_128_PA_ROUNDS) << 40) |    \
   ((uint64_t)(ASCON_128_PB_ROUNDS) << 32))



typedef struct {
	uint64_t x[5];
} state_t;


/* set byte in 64-bit Ascon word */
#define SETBYTE(b, i) ((uint64_t)(b) << (56 - 8 * (i)))

/* get byte from 64-bit Ascon word */
#define GETBYTE(x, i) ((uint8_t)((uint64_t)(x) >> (56 - 8 * (i))))


/* load bytes into 64-bit Ascon word */
static inline uint64_t LOADBYTES(const uint8_t* bytes, int n) {
	uint64_t x = 0;
	for (int i = 0; i < n; ++i) x |= SETBYTE(bytes[i], i);
	return x;
}


static inline uint64_t ROR(uint64_t x, int n) {
	return x >> n | x << (-n & 63);
}

/* store bytes from 64-bit Ascon word */
static inline void STOREBYTES(uint8_t* bytes, uint64_t x, int n) {
	for (int i = 0; i < n; ++i) bytes[i] = GETBYTE(x, i);
}

/* set padding byte in 64-bit Ascon word */
#define PAD(i) SETBYTE(0x80, i)

/* clear bytes in 64-bit Ascon word */
static inline uint64_t CLEARBYTES(uint64_t x, int n) {
	for (int i = 0; i < n; ++i) x &= ~SETBYTE(0xff, i);
	return x;
}

static inline void ROUND(state_t* s, uint8_t C) {
	state_t t;
	/* addition of round constant */
	s->x[2] ^= C;
	/* printstate(" round constant", s); */
	/* substitution layer */
	s->x[0] ^= s->x[4];
	s->x[4] ^= s->x[3];
	s->x[2] ^= s->x[1];
	/* start of keccak s-box */
	t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
	t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
	t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
	t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
	t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);
	/* end of keccak s-box */
	t.x[1] ^= t.x[0];
	t.x[0] ^= t.x[4];
	t.x[3] ^= t.x[2];
	t.x[2] = ~t.x[2];
	/* printstate(" substitution layer", &t); */
	/* linear diffusion layer */
	s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
	s->x[1] = t.x[1] ^ ROR(t.x[1], 61) ^ ROR(t.x[1], 39);
	s->x[2] = t.x[2] ^ ROR(t.x[2], 1) ^ ROR(t.x[2], 6);
	s->x[3] = t.x[3] ^ ROR(t.x[3], 10) ^ ROR(t.x[3], 17);
	s->x[4] = t.x[4] ^ ROR(t.x[4], 7) ^ ROR(t.x[4], 41);
}

static inline void P12(state_t* s) {
	ROUND(s, 0xf0);
	ROUND(s, 0xe1);
	ROUND(s, 0xd2);
	ROUND(s, 0xc3);
	ROUND(s, 0xb4);
	ROUND(s, 0xa5);
	ROUND(s, 0x96);
	ROUND(s, 0x87);
	ROUND(s, 0x78);
	ROUND(s, 0x69);
	ROUND(s, 0x5a);
	ROUND(s, 0x4b);
}

static inline void P6(state_t* s) {
	ROUND(s, 0x96);
	ROUND(s, 0x87);
	ROUND(s, 0x78);
	ROUND(s, 0x69);
	ROUND(s, 0x5a);
	ROUND(s, 0x4b);
}



#endif //ASCON_1_DEF_H

