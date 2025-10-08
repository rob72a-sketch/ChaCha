// APP.h
#ifndef __APP_H__
#define __APP_H__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

//----------------------------------------------
#if defined(__cplusplus) && (__cplusplus >= 201103L)
        #include <stdexcept>
        #include <exception>
#endif
#ifndef APP_THROW_INVALID_ARG
    #ifdef __cplusplus
            #if __cplusplus >= 201103L
               #define APP_THROW_INVALID_ARG(msg) {throw std::invalid_argument(msg);}
            #else
               #define APP_THROW_INVALID_ARG(msg) {throw msg;}
            #endif
    #else
        #define APP_THROW_INVALID_ARG(msg) {fprintf(stderr,"%s\n",msg);abort();}
    #endif
#endif
//----------------------------------------------
#ifndef APP_NULLPTR
    #if defined(__cplusplus) && (__cplusplus >= 201103L)
        #define APP_NULLPTR nullptr
    #else
        #define APP_NULLPTR NULL
    #endif
#endif
//----------------------------------------------
#ifndef APP_NO_OPTIMIZE
    #if defined( __GNUC__ )
        #define APP_NO_OPTIMIZE __attribute__((optimize("O0")))
        #define APP_xNO_OPTIMIZE
    #elif defined(_MSC_VER)
        #define APP_NO_OPTIMIZE __pragma(optimize("", off))
        #define APP_xNO_OPTIMIZE __pragma optimize("", on)
    #else
        #define APP_NO_OPTIMIZE
        #define APP_xNO_OPTIMIZE
    #endif
#endif

#ifndef APP_FAST_OPTIMIZE
    #if defined( __GNUC__ )
        #define APP_FAST_OPTIMIZE __attribute__((optimize("Ofast")))
        #define APP_xFAST_OPTIMIZE
    #elif defined(_MSC_VER)
        #define APP_FAST_OPTIMIZE __pragma(optimize("t", on))
        #define APP_xFAST_OPTIMIZE __pragma(optimize("", on))
    #else
        #define APP_FAST_OPTIMIZE
        #define APP_xFAST_OPTIMIZE
    #endif
#endif
//----------------------------------------------
#ifndef APP_ROTL32
APP_FAST_OPTIMIZE
static inline uint32_t app_rotl32(uint32_t x, int n)
{
    return x << n | (x >> (-n & 31));
}
APP_xFAST_OPTIMIZE
	#define APP_ROTL32 app_rotl32
#endif
//----------------------------------------------
#ifndef APP_BZERO
APP_FAST_OPTIMIZE
void inline app_bzero(void* _buf_ptr, size_t _bufsize)
{
	size_t i, m;
	unsigned long *wbuf_ptr = (unsigned long *)_buf_ptr;
	unsigned char *cbuf_ptr;

	for(i = 0, m = _bufsize / sizeof(unsigned long); i < m; i++)
   		*(wbuf_ptr++) = 0;

	cbuf_ptr = (unsigned char*)wbuf_ptr;

	for(i = 0, m = _bufsize % sizeof(unsigned long); i < m; i++)
   		*(cbuf_ptr++) = 0;
}
APP_xFAST_OPTIMIZE
#define APP_BZERO(b,n)    app_bzero((b),(n))
#endif
//----------------------------------------------
#ifndef APP_BSZERO
	static inline void app_bszero(void* _buf_ptr, size_t _bufsize)
	{
	    volatile unsigned char *v_cbuf_ptr = (volatile unsigned char*)_buf_ptr;

	    for (size_t i = 0; i < _bufsize; i++)
	    {
	        v_cbuf_ptr[i] = 0;
	    }
	}
    #define APP_BSZERO(b,n) app_bszero(b,n)
#endif
//----------------------------------------------
#ifndef APP_MCPY
APP_FAST_OPTIMIZE
void inline app_memcpy( void* _dst, const void* _src, int _n)
{
	int i, m;
	unsigned long  *wdst = (unsigned long  *)_dst;
	unsigned long  *wsrc = (unsigned long  *)_src;
	unsigned char  *cdst, *csrc;

	for(i = 0, m = _n / sizeof(long); i < m; i++)
	   *(wdst++) = *(wsrc++);

	cdst = (unsigned char*)wdst;
	csrc = (unsigned char*)wsrc;

	for(i = 0, m = _n % sizeof(long); i < m; i++)
	   *(cdst++) = *(csrc++);
}
APP_xFAST_OPTIMIZE
	#define APP_MCPY(d,s,n)   app_memcpy((d),(s),(n))
#endif
//----------------------------------------------

	#define APP_MALLOC        malloc
	#define APP_FREE          free

#ifndef APP_MLOCK
	#include <windows.h>
	#define APP_MLOCK         ::VirtualLock
	#define APP_MUNLOCK       ::VirtualUnlock
#endif

#ifndef APP_LOG2
    #define APP_LOG2(x) (log(x) / log(2))
#endif
#ifndef APP_MIN
    #define APP_MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef APP_MAX
    #define APP_MAX(a,b) ((a)>(b)?(a):(b))
#endif
#ifndef APP_BUF8GETBIT
    #define APP_BUF8GETBIT(buf,i) ((bool)((buf)[(i)/8]&(1u<<((i)%8))))
    #define APP_BUF8SETBIT(buf,i) {(buf)[(i)/8]|=(1u<<((i)%8));}
    #define APP_BUF8CLRBIT(buf,i) {(buf)[(i)/8]&=~(1u<<((i)%8));}
    #define APP_BUF8TOGGLEBIT(buf,i) {(buf)[(i)/8]^=(1u<<((i)%8));}
#endif
//------------------------------------------------------
#endif
