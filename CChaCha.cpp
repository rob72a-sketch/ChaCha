// CChaCha.cpp
#include "CChaCha.h"

//--------------------------------------------
    void CChaCha::DBG_OutState(FILE* _fp)
    {
        uint8_t k[32];

        fprintf(_fp, "\n\n======= <ChaCha state> =======\n");
        fprintf(_fp, "CONST:\n");

                for(int i = 0; i < 4; i++)
                {
                    fprintf(_fp, "%08X ", this->FFState[i]);
                }

        APP_BZERO(&k[0], 32);

        fprintf(_fp, "\n\nKEY:\n");

                for(int i = 4; i < 12; i++)
                {
                    CChaCha_u32t8le(this->FFState[i], &k[0]);

                        for(int j = 0; j < 4; j++)
                        {
                            fprintf(_fp, "%02X ", k[j]);
                        }

                    fprintf(_fp, "\n");
                }

        APP_BZERO(&k[0], 32);

        fprintf(_fp, "\n\nCOUNTER:\n");
        fprintf(_fp, "%08X ", this->FFState[12]);

        fprintf(_fp, "\n\nNONCE:\n");

                for(int i = 13; i < 16; i++)
                {
                    CChaCha_u32t8le(this->FFState[i], &k[0]);

                        for(int j = 0; j < 4; j++)
                        {
                            printf("%02X ", k[j]);
                        }

                    fprintf(_fp, "\n");
                }

        fprintf(_fp, "\n======= </ChaCha state> =======\n\n");
        APP_BSZERO(&k[0], 32);
    }
//--------------------------------------------
    float CChaCha::ShannonEntropy_8(const void* _pData, size_t _BufNBytes)
    {
            if (_BufNBytes == 0)
            {
                return 0.0; // Handle empty input
            }

        size_t i;
        const uint8_t* pData = (uint8_t*)_pData;
        unsigned int counts[256] = {0};

            for (i = 0; i < _BufNBytes; i++)
            {
                counts[(uint8_t)pData[i]]++;
            }

        float entropy = 0.0;

            for (i = 0; i < 256; i++)
            {
                if (counts[i] > 0)
                {
                    float p = (float)counts[i] / _BufNBytes;
                    entropy -= p * APP_LOG2(p);
                }
            }

        return entropy;
    }
//---------------------------------------
    float CChaCha::ShannonEntropy_1
                        (
                            const void* _pData,
                            size_t      _BufNBytes,
                            bool        _SignificantBitsOnly,
                            bool        _BE,
                            size_t*     _OUT_pExtraNBits
                        )
    {
        // Little Endian Bit Order (для ChaCha)
        static const uint8_t w[8] = {0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80};
        const uint8_t* pData      = (const uint8_t*)_pData;
        long long counts[2]       = {0, 0};
        float entropy             = 0.0;

        // Флаг для пропуска ведущих нулей.
        // Если _SignificantBitsOnly = false, то fnd = true, и мы ничего не пропускаем.
        bool fnd = !_SignificantBitsOnly;

        // --- 1. Единый цикл подсчета ---
        for (size_t iByte = 0; iByte < _BufNBytes; iByte++)
        {
            // Определяем порядок байтов: LE (iByte) или BE (_BufNBytes - iByte - 1)
            size_t di8 = _BE ? _BufNBytes - iByte - 1 : iByte;
            uint8_t currentByte = pData[di8];

            for (size_t iBit = 0; iBit < 8; iBit++)
            {
                // Определяем порядок битов: LE (iBit) или BE (7 - iBit)
                size_t di1 = _BE ? 7 - iBit : iBit;

                // Проверяем бит
                bool bitIsOne = (currentByte & w[di1]);

                // Активируем флаг, если найден первый значащий бит
                fnd |= bitIsOne;

                if (fnd)
                {
                    // Считаем только после нахождения первого значащего бита
                    counts[(int)bitIsOne] ++;
                }
            }
        }

        // --- 2. Расчет энтропии ---

        size_t totalBits = counts[0] + counts[1];
        if (totalBits == 0) return 0.0f;

            if(_SignificantBitsOnly && _OUT_pExtraNBits)
            {
                *_OUT_pExtraNBits =
                    (_BufNBytes / 8) - totalBits;
            }

        // Используем totalBits в качестве знаменателя
        for (int i = 0; i < 2; i++)
        {
            if (counts[i] > 0)
            {
                float p = (float)counts[i] / totalBits;
                entropy -= p * APP_LOG2(p);
            }
        }

        return entropy;
    }
//---------------------------------------
    float CChaCha::EntropyOfState()
    {
        uint8_t x[64];
        float rv;
        this->FFserialize(this->FFState, x);
        rv = CChaCha::ShannonEntropy_1(x, 64, false, true, NULL);
        APP_BSZERO(x, 64);
        return rv;
    }
//---------------------------------------
    void CChaCha::SetNumRounds(uint8_t _NumRounds)
    {
        this->FNumRounds = _NumRounds;
    }
//---------------------------------------
    void CChaCha::SetCounter(uint32_t _Counter)
    {
        this->FFState[12] = _Counter;
    }
//---------------------------------------
    uint32_t CChaCha::GetCounter()
    {
        return this->FFState[12];
    }
//---------------------------------------
    void CChaCha::SetKey(const uint8_t _KeyBuf[32])
    {
        this->FFState[4]  = CChaCha_u8t32le(&_KeyBuf[0]);
        this->FFState[5]  = CChaCha_u8t32le(&_KeyBuf[4]);
        this->FFState[6]  = CChaCha_u8t32le(&_KeyBuf[8]);
        this->FFState[7]  = CChaCha_u8t32le(&_KeyBuf[12]);
        this->FFState[8]  = CChaCha_u8t32le(&_KeyBuf[16]);
        this->FFState[9]  = CChaCha_u8t32le(&_KeyBuf[20]);
        this->FFState[10] = CChaCha_u8t32le(&_KeyBuf[24]);
        this->FFState[11] = CChaCha_u8t32le(&_KeyBuf[28]);
    }
//---------------------------------------
    void CChaCha::SetNonce(const uint8_t _NonceBuf[12])
    {
        this->FFState[13] = CChaCha_u8t32le(&_NonceBuf[0]);
        this->FFState[14] = CChaCha_u8t32le(&_NonceBuf[4]);
        this->FFState[15] = CChaCha_u8t32le(&_NonceBuf[8]);
    }
//---------------------------------------
    void CChaCha::IncrementNonce()
    {
           ++this->FFState[13]
        || ++this->FFState[14]
        || ++this->FFState[15];
    }
//---------------------------------------
    CChaCha::CChaCha()
    {
        const uint8_t K[32] = CChaCha_DBG_DEFAULT_KEY;
        const uint8_t N[12] = CChaCha_DBG_DEFAULT_NONCE;

        // The first four words (0-3) are constants:
        // 0x61707865, 0x3320646e,0x79622d32, 0x6b206574
        APP_MLOCK(&this->FFState[0], 16 * sizeof(uint32_t));
        this->FFState[0] = 0x61707865;
        this->FFState[1] = 0x3320646e;
        this->FFState[2] = 0x79622d32;
        this->FFState[3] = 0x6b206574;
        this->SetKey(K);
        this->SetNonce(N);
        this->SetCounter(1);
    }
//---------------------------------------
    CChaCha::CChaCha
                (
                 const uint8_t _key[32],
                 const uint8_t _nonce[12],
                 uint32_t      _counter
                )
    {
        // The first four words (0-3) are constants:
        // 0x61707865, 0x3320646e,0x79622d32, 0x6b206574
        APP_MLOCK(&this->FFState[0], 16 * sizeof(uint32_t));
        this->FFState[0] = 0x61707865;
        this->FFState[1] = 0x3320646e;
        this->FFState[2] = 0x79622d32;
        this->FFState[3] = 0x6b206574;
        this->SetKey(_key);
        this->SetNonce(_nonce);
        this->SetCounter(1);
    }
//---------------------------------------
APP_NO_OPTIMIZE
    CChaCha::~CChaCha()
    {
        APP_BSZERO(this->FFState, 16 * sizeof(uint32_t));
        this->SetCounter(0);
        APP_MUNLOCK(&this->FFState[0], 16 * sizeof(uint32_t));
    }
APP_xNO_OPTIMIZE
//---------------------------------------
	void CChaCha::FFserialize(uint32_t _inbuf[16], uint8_t _outbuf[64])
    {
        for (int i = 0; i < 16; i++)
        {
            CChaCha_u32t8le(_inbuf[i], &_outbuf[i*4]);
        }
    }
//---------------------------------------
    void CChaCha::encryptBlock(uint32_t _InBuf[16], uint8_t _OutBuf[64])
	{
	    uint32_t x[16];

	    for(int i = 0; i < 16; i++)
        {
             x[i] = _InBuf[i];
        }

	    for (int i = this->FNumRounds; i > 0; i -= 2)
	    {
	        CChaCha_quarterRound(x, 0, 4,  8, 12);
	        CChaCha_quarterRound(x, 1, 5,  9, 13);
	        CChaCha_quarterRound(x, 2, 6, 10, 14);
	        CChaCha_quarterRound(x, 3, 7, 11, 15);
	        CChaCha_quarterRound(x, 0, 5, 10, 15);
	        CChaCha_quarterRound(x, 1, 6, 11, 12);
	        CChaCha_quarterRound(x, 2, 7,  8, 13);
	        CChaCha_quarterRound(x, 3, 4,  9, 14);
	    }

	    for (int i = 0; i < 16; i++)
	    {
	        x[i] += this->FFState[i];
	    }

	    CChaCha::FFserialize(x, _OutBuf);
	    APP_BSZERO(&x[0], 64);
	}
//---------------------------------------
    // Приватный метод в классе CChaCha для перемешивания состояния
    void CChaCha::FFMixState(int rounds)
    {
        // Временная копия состояния для выполнения раундов.
        // Это важно, чтобы не портить исходное состояние FFState до XOR'а.
        uint32_t x[16];
        APP_MCPY(x, this->FFState, sizeof(x));

        // Используем вашу логику цикла, где rounds - это количество полных ChaCha раундов
        // (например, 10 для 20 четверть-раундов).
        for (int i = rounds; i > 0; --i)
        {
            // Column Rounds
            CChaCha_quarterRound(x, 0, 4,  8, 12);
            CChaCha_quarterRound(x, 1, 5,  9, 13);
            CChaCha_quarterRound(x, 2, 6, 10, 14);
            CChaCha_quarterRound(x, 3, 7, 11, 15);

            // Diagonal Rounds
            CChaCha_quarterRound(x, 0, 5, 10, 15);
            CChaCha_quarterRound(x, 1, 6, 11, 12);
            CChaCha_quarterRound(x, 2, 7,  8, 13);
            CChaCha_quarterRound(x, 3, 4,  9, 14);
        }

        // Результат: XOR'им смешанное состояние обратно в текущий ключ
        // Это и есть криптографическое усиление ключа (Key Augmentation)
        for (int j = 4; j < 12; ++j)
        {
            this->FFState[j] ^= x[j];
        }
      APP_BSZERO(&x[0], 16 * sizeof(uint32_t));
    }
//---------------------------------------
    void CChaCha::Reseed(const void* _pData, size_t _nBytes)
    {
        const uint8_t* pEntropy = (const uint8_t*)_pData;
        size_t i = 0;
        int stateWordIndex = 4; // Начинаем с ключа

        while (i + 4 <= _nBytes)
        {
            uint32_t entropyWord = CChaCha_u8t32le(&pEntropy[i]);

            // XOR'им энтропию в текущее слово (циклично Key/Counter/Nonce)
            // Используем 12 слов для XOR (Key: 4-11, Counter/Nonce: 12-15)
            this->FFState[stateWordIndex % 12 + 4] ^= entropyWord;

            i += 4;
            stateWordIndex++;

            // После каждого заполнения ключевой области (8 слов = 32 байта) - перемешиваем
            if ((stateWordIndex - 4) % 8 == 0)
            {
                // Выполняем 10 полных раундов для криптографического смешивания
                this->FFMixState(10);
                // Перезапускаем счетчик, т.к. состояние уже перемешано.
                this->FFState[12] = 1;
            }
        }

        // Финальное перемешивание, если осталась частичная порция
        if ((stateWordIndex - 4) % 8 != 0)
        {
            this->FFMixState(10);
        }

        // Сброс счетчика, если он не был сброшен в цикле
        this->FFState[12] = 1;
    }
//---------------------------------------
	void CChaCha::EncDec(void* _pInBuf, uint32_t _BufLen, uint8_t* _pOutBuf)
	{
	    uint8_t* pInBuf =
                    _pInBuf ?
                    (uint8_t*)_pInBuf :
                    NULL;

	    uint8_t  block[64];

	    for (uint32_t i = 0; i < _BufLen; i += 64)
	    {
	        this->encryptBlock(this->FFState, block);
	        this->FFState[12]++;//Counter++

	        if(pInBuf)
            {
                for (uint32_t j = i; j < i + 64; j++)
                {
                    if (j >= _BufLen)
                        { break; }

                    _pOutBuf[j] = pInBuf[j] ^ block[j - i];
                }
            }
            else
            {
                for (uint32_t j = i; j < i + 64; j++)
                {
                    if (j >= _BufLen)
                        { break; }

                    _pOutBuf[j] = block[j - i];
                }
            }
	    }
	  APP_BSZERO(&block[0], 64);
	}
//---------------------------------------
	void CChaCha::RndToBuf(uint8_t* _pOutBuf, uint32_t _OutBufLen)
	{
        this->EncDec(NULL, _OutBufLen, _pOutBuf);
	}
//---------------------------------------
