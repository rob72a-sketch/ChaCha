// CChaCha.h
#ifndef __CChaCha_H__
#define __CChaCha_H__
// Prototype:
// https://blog.lhs.su/programming/dlang/potochnyj-algoritm-shifrovaniya-chacha/
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "APP.h"

#define CChaCha_DBG_DEFAULT_KEY \
{                               \
    0xD1, 0x31, 0x0B, 0xA6,     \
    0x98, 0xDF, 0xB5, 0xAC,     \
    0x2F, 0xFD, 0x72, 0xDB,     \
    0xD0, 0x1A, 0xDF, 0xB7,     \
    0xB8, 0xE1, 0xAF, 0xED,     \
    0x6A, 0x26, 0x7E, 0x96,     \
    0xBA, 0x7C, 0x90, 0x45,     \
    0xF1, 0x2C, 0x7F, 0x99,     \
};

#define CChaCha_DBG_DEFAULT_NONCE \
{                                 \
    0x24, 0xA1, 0x99, 0x47,       \
    0xB3, 0x91, 0x6C, 0xF7,       \
    0x08, 0x01, 0xF2, 0xE2,       \
};

APP_FAST_OPTIMIZE
void inline CChaCha_u32t8le(uint32_t _v, uint8_t* _p)
{
    _p[0] = _v & 0xff;
    _p[1] = (_v >> 8) & 0xff;
    _p[2] = (_v >> 16) & 0xff;
    _p[3] = (_v >> 24) & 0xff;
}
APP_xFAST_OPTIMIZE

APP_FAST_OPTIMIZE
uint32_t inline CChaCha_u8t32le(const uint8_t* p)
{
    register uint32_t value = p[3];
    value = (value << 8) | p[2];
    value = (value << 8) | p[1];
    value = (value << 8) | p[0];
    return value;
}
APP_xFAST_OPTIMIZE

/*static inline uint32_t rotl32b(uint32_t x, int n)
{
    return ((x<<(n)) | (x>>(8*sizeof(x)-(n))));
}*/

APP_FAST_OPTIMIZE
static inline uint32_t CChaCha_rotl32(uint32_t x, int n)
{
    return x << n | (x >> (-n & 31));
}
APP_xFAST_OPTIMIZE

APP_FAST_OPTIMIZE
static inline void CChaCha_quarterRound(uint32_t _x[16], int _a, int _b, int _c, int _d)
{
    _x[_a] += _x[_b]; _x[_d] = CChaCha_rotl32(_x[_d] ^ _x[_a], 16);
    _x[_c] += _x[_d]; _x[_b] = CChaCha_rotl32(_x[_b] ^ _x[_c], 12);
    _x[_a] += _x[_b]; _x[_d] = CChaCha_rotl32(_x[_d] ^ _x[_a],  8);
    _x[_c] += _x[_d]; _x[_b] = CChaCha_rotl32(_x[_b] ^ _x[_c],  7);
}
APP_xFAST_OPTIMIZE

#ifndef APP_LOG2
    #define APP_LOG2(x) (log(x) / log(2))
#endif

class CChaCha
{
    public:
        CChaCha();
        CChaCha
            (
             const uint8_t _key[32],
             const uint8_t _nonce[12],
             uint32_t      _counter
            );
        virtual ~CChaCha();

        void  DBG_OutState(FILE* _fp);
        float EntropyOfState();

        static float ShannonEntropy_1
                        (
                            const void* _pData,
                            size_t      _BufNBytes,
                            bool        _SignificantBitsOnly,
                            bool        _BE,
                            size_t*     _OUT_pExtraNBits
                        );
        static float ShannonEntropy_8(const void* _pData, size_t _BufNBytes);
        void         SetCounter(uint32_t _Counter);
        uint32_t     GetCounter();
        void         SetKey(const uint8_t _KeyBuf[32]);
        void         SetNonce(const uint8_t _NonceBuf[12]);
        void         IncrementNonce();
        void         encryptBlock(uint32_t _InBuf[16], uint8_t _OutBuf[64]);
        void         Reseed(const void* _pData, size_t nBytes);
        void         EncDec(void* _pInBuf, uint32_t _length, uint8_t* _pOutBuf);
        void         RndToBuf(uint8_t* _pOutBuf, uint32_t _OutBufLen);
        void         SetNumRounds(uint8_t _NumRounds);

    protected:
        uint8_t   FNumRounds;

    private:
		uint32_t  FFState[16];
		void      FFMixState(int rounds);
		//
        static void FFserialize(uint32_t _inbuf[16], uint8_t _outbuf[64]);
};
#endif // __CChaCha_H__
