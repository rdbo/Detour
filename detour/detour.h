//Made by rdbo
//https://github.com/rdbo/Detour

#pragma once
#ifndef DETOUR

//## Defines

//Operating System
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__) && !defined(linux)
#define DETOUR_WIN
#elif defined(linux)
#define DETOUR_LINUX
#endif

//Architecture

#if defined(_M_IX86) || defined(__i386__)
#define DETOUR_86
#elif defined(_M_X64) || defined(__LP64__) || defined(_LP64)
#define DETOUR_64
#endif

//Limits

#define DETOUR_MAX_COUNT 256
#define DETOUR_MAX_SIZE  64

//Protection

#if defined(DETOUR_WIN)
#elif defined(DETOUR_LINUX)
#define DETOUR_PROT_EXEC           PROT_EXEC
#define DETOUR_PROT_READ           PROT_READ
#define DETOUR_PROT_WRITE          PROT_WRITE
#endif
#define DETOUR_PROT_EXEC_READWRITE DETOUR_PROT_EXEC | DETOUR_PROT_READ | DETOUR_PROT_WRITE

//Detour methods

#define DETOUR_METHOD0 0
//mov *ax, ABS_ADDR
//jmp *ax

#define DETOUR_METHOD1 1
//jmp REL_ADDR

#define DETOUR_METHOD2 2
//mov *ax, ABS_ADDR
//push *ax
//ret

#define DETOUR_METHOD3 3
//push ABS_ADDR_DWORD
//ret

#define DETOUR_METHOD4 4
//mov *ax, ABS_ADDR
//call *ax

#define DETOUR_METHOD5 5
//call REL_ADDR

//Assembly

#define _DETOUR_JMP        0xE9
#define _DETOUR_JMP_RAX    0xFF, 0xE0
#define _DETOUR_JMP_EAX    0xFF, 0xE0
#define _DETOUR_CALL       0xE8
#define _DETOUR_CALL_EAX   0xFF, 0xD0
#define _DETOUR_CALL_RAX   0xFF, 0xD0
#define _DETOUR_MOVABS_RAX 0x48, 0xB8
#define _DETOUR_MOV_EAX    0xB8
#define _DETOUR_PUSH       0x68
#define _DETOUR_PUSH_RAX   0x50
#define _DETOUR_PUSH_EAX   0x50
#define _DETOUR_RET        0xC3
#define _DETOUR_BYTE       0x0
#define _DETOUR_WORD       0x0, 0x0
#define _DETOUR_DWORD      0x0, 0x0, 0x0, 0x0
#define _DETOUR_QWORD      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0

//Functions

#define PP_NARG(...) \
         PP_NARG_(__VA_ARGS__,PP_RSEQ_N())
#define PP_NARG_(...) \
         PP_ARG_N(__VA_ARGS__)
#define PP_ARG_N( \
          _1, _2, _3, _4, _5, _6, _7, _8, _9,_10, \
         _11,_12,_13,_14,_15,_16,_17,_18,_19,_20, \
         _21,_22,_23,_24,_25,_26,_27,_28,_29,_30, \
         _31,_32,_33,_34,_35,_36,_37,_38,_39,_40, \
         _41,_42,_43,_44,_45,_46,_47,_48,_49,_50, \
         _51,_52,_53,_54,_55,_56,_57,_58,_59,_60, \
         _61,_62,_63,N,...) N
#define PP_RSEQ_N() \
         63,62,61,60,                   \
         59,58,57,56,55,54,53,52,51,50, \
         49,48,47,46,45,44,43,42,41,40, \
         39,38,37,36,35,34,33,32,31,30, \
         29,28,27,26,25,24,23,22,21,20, \
         19,18,17,16,15,14,13,12,11,10, \
         9,8,7,6,5,4,3,2,1,0

#define _BUFFER_GENERATE(...) { __VA_ARGS__ }
#define ASM_GENERATE(...) _BUFFER_GENERATE(__VA_ARGS__)
#define _CALC_ARG_LENGTH(...) PP_NARG(__VA_ARGS__)
#define CALC_ARG_LENGTH(...) _CALC_ARG_LENGTH(__VA_ARGS__)
#define CALC_ASM_LENGTH(...) CALC_ARG_LENGTH(__VA_ARGS__)

//Other

#define BAD_RETURN -1

//Compatibility
#define DETOUR_COMPATIBLE (defined(DETOUR_86) || defined(DETOUR_64)) && (defined(DETOUR_WIN) || defined(DETOUR_LINUX))

#if DETOUR_COMPATIBLE

//## Includes
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#if defined(DETOUR_WIN)
#elif defined(DETOUR_LINUX)
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/uio.h>
#endif

//## Types

typedef uint8_t  byte_t;
typedef uint16_t word_t;
typedef uint32_t dword_t;
typedef uint64_t qword_t;
typedef byte_t*  buffer_t;
typedef void*    addr_t;
typedef char*    str_t;

#if defined(DETOUR_86)
typedef dword_t mem_t;
#elif defined(DETOUR_64)
typedef qword_t mem_t;
#endif

//## Detour

struct detour_list
{
    addr_t address;
    byte_t buffer[DETOUR_MAX_SIZE];
};

int DetourRestore(addr_t src);
int DetourLength(int method);
int DetourProtect(addr_t src, size_t size, int protection);
int Detour(addr_t src, addr_t dst, size_t size, int method);
addr_t DetourTrampoline(addr_t src, addr_t dst, size_t size, int method);

#endif //DETOUR_COMPATIBLE
#define DETOUR
#endif //DETOUR
