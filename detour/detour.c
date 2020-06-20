#include "detour.h"
#if defined(DETOUR) && DETOUR_COMPATIBLE

//Detour

//Variables/buffers

const byte_t DETOUR_JMP[]        = ASM_GENERATE(_DETOUR_JMP);
const byte_t DETOUR_JMP_RAX[]    = ASM_GENERATE(_DETOUR_JMP_RAX);
const byte_t DETOUR_JMP_EAX[]    = ASM_GENERATE(_DETOUR_JMP_EAX);
const byte_t DETOUR_CALL[]       = ASM_GENERATE(_DETOUR_CALL);
const byte_t DETOUR_CALL_EAX[]   = ASM_GENERATE(_DETOUR_CALL_EAX);
const byte_t DETOUR_CALL_RAX[]   = ASM_GENERATE(_DETOUR_CALL_RAX);
const byte_t DETOUR_MOVABS_RAX[] = ASM_GENERATE(_DETOUR_MOVABS_RAX);
const byte_t DETOUR_MOV_EAX[]    = ASM_GENERATE(_DETOUR_MOV_EAX);
const byte_t DETOUR_PUSH[]       = ASM_GENERATE(_DETOUR_PUSH);
const byte_t DETOUR_PUSH_RAX[]   = ASM_GENERATE(_DETOUR_PUSH_RAX);
const byte_t DETOUR_PUSH_EAX[]   = ASM_GENERATE(_DETOUR_PUSH_EAX);
const byte_t DETOUR_RET[]        = ASM_GENERATE(_DETOUR_RET);
const byte_t DETOUR_BYTE[]       = ASM_GENERATE(_DETOUR_BYTE);
const byte_t DETOUR_WORD[]       = ASM_GENERATE(_DETOUR_WORD);
const byte_t DETOUR_DWORD[]      = ASM_GENERATE(_DETOUR_DWORD);
const byte_t DETOUR_QWORD[]      = ASM_GENERATE(_DETOUR_QWORD);

//Functions

int DetourLength(int method)
{
    switch(method)
    {
#       if defined(DETOUR_86)
        case DETOUR_METHOD0: return CALC_ASM_LENGTH(_DETOUR_MOV_EAX, _DETOUR_DWORD, _DETOUR_JMP_EAX); break;
        case DETOUR_METHOD1: return CALC_ASM_LENGTH(_DETOUR_JMP, _DETOUR_DWORD); break;
        case DETOUR_METHOD2: return CALC_ASM_LENGTH(_DETOUR_MOV_EAX, _DETOUR_DWORD, _DETOUR_PUSH_EAX, _DETOUR_RET); break;
        case DETOUR_METHOD3: return CALC_ASM_LENGTH(_DETOUR_PUSH, _DETOUR_DWORD, _DETOUR_RET); break;
        case DETOUR_METHOD4: return CALC_ASM_LENGTH(_DETOUR_MOV_EAX, _DETOUR_DWORD, _DETOUR_CALL_EAX); break;
        case DETOUR_METHOD5: return CALC_ASM_LENGTH(_DETOUR_CALL, _DETOUR_DWORD); break;
#       elif defined(DETOUR_64)
        case DETOUR_METHOD0: return CALC_ASM_LENGTH(_DETOUR_MOVABS_RAX, _DETOUR_QWORD, _DETOUR_JMP_RAX); break;
        case DETOUR_METHOD1: return CALC_ASM_LENGTH(_DETOUR_JMP, _DETOUR_DWORD); break;
        case DETOUR_METHOD2: return CALC_ASM_LENGTH(_DETOUR_MOVABS_RAX, _DETOUR_QWORD, _DETOUR_PUSH_RAX, _DETOUR_RET); break;
        case DETOUR_METHOD3: return CALC_ASM_LENGTH(_DETOUR_PUSH, _DETOUR_DWORD, _DETOUR_RET); break;
        case DETOUR_METHOD4: return CALC_ASM_LENGTH(_DETOUR_MOVABS_RAX, _DETOUR_QWORD, _DETOUR_CALL_RAX); break;
        case DETOUR_METHOD5: return CALC_ASM_LENGTH(_DETOUR_CALL, _DETOUR_DWORD); break;
#       endif
    }

    return BAD_RETURN;
}

int DetourProtect(addr_t src, size_t size, int protection)
{
#   if defined(DETOUR_WIN)
#   elif defined(DETOUR_LINUX)
    long pagesize = sysconf(_SC_PAGE_SIZE);
	src = (addr_t)((mem_t)src - ((mem_t)src % pagesize));
	return mprotect(src, size, protection);
#   endif
    return BAD_RETURN;
}

addr_t DetourAllocate(size_t size, int protection)
{
    #if defined(DETOUR_WIN)
    #elif defined(DETOUR_LINUX)
    return mmap(NULL, size, protection, MAP_ANON | MAP_PRIVATE, -1, 0);
    #endif
}

int Detour(addr_t src, addr_t dst, size_t size, int method)
{
    int detour_size = DetourLength(method);
    if(detour_size == BAD_RETURN || size < detour_size || DetourProtect(src, size, DETOUR_PROT_EXEC_READWRITE) != 0) return BAD_RETURN;

    switch(method)
    {
#       if defined(DETOUR_86)
        case DETOUR_METHOD0:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_DETOUR_MOV_EAX, _DETOUR_DWORD, _DETOUR_JMP_EAX);
            *(dword_t*)((mem_t)detour_buffer + sizeof(DETOUR_MOV_EAX)) = (dword_t)dst;
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }
        break;

        case DETOUR_METHOD1:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_DETOUR_JMP, _DETOUR_DWORD);
            *(dword_t*)((mem_t)detour_buffer + sizeof(DETOUR_JMP)) = (dword_t)((mem_t)dst - (mem_t)src - detour_size);
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }
        break;

        case DETOUR_METHOD2:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_DETOUR_MOV_EAX, _DETOUR_DWORD, _DETOUR_PUSH_EAX, _DETOUR_RET);
            *(dword_t*)((mem_t)detour_buffer + sizeof(DETOUR_MOV_EAX)) = (dword_t)dst;
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }
        break;

        case DETOUR_METHOD3:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_DETOUR_PUSH, _DETOUR_DWORD, _DETOUR_RET);
            *(dword_t*)((mem_t)detour_buffer + sizeof(DETOUR_PUSH)) = (dword_t)dst;
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }
        break;

        case DETOUR_METHOD4:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_DETOUR_MOV_EAX, _DETOUR_DWORD, _DETOUR_CALL_EAX);
            *(dword_t*)((mem_t)detour_buffer + sizeof(DETOUR_MOV_EAX)) = (dword_t)dst;
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }
        break;

        case DETOUR_METHOD5:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_DETOUR_CALL, _DETOUR_DWORD);
            *(dword_t*)((mem_t)detour_buffer + sizeof(DETOUR_CALL)) = (dword_t)((mem_t)dst - (mem_t)src - detour_size);
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }
        break;

#       elif defined(DETOUR_64)
        case DETOUR_METHOD0:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_DETOUR_MOVABS_RAX, _DETOUR_QWORD, _DETOUR_JMP_RAX);
            *(qword_t*)((mem_t)detour_buffer + sizeof(DETOUR_MOVABS_RAX)) = (qword_t)dst;
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }
        break;

        case DETOUR_METHOD1:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_DETOUR_JMP, _DETOUR_DWORD);
            *(dword_t*)((mem_t)detour_buffer + sizeof(DETOUR_JMP)) = (dword_t)((mem_t)dst - (mem_t)src - detour_size);
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }
        break;

        case DETOUR_METHOD2:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_DETOUR_MOVABS_RAX, _DETOUR_QWORD, _DETOUR_PUSH_RAX, _DETOUR_RET);
            *(qword_t*)((mem_t)detour_buffer + sizeof(DETOUR_MOVABS_RAX)) = (qword_t)dst;
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }
        break;

        case DETOUR_METHOD3:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_DETOUR_PUSH, _DETOUR_DWORD, _DETOUR_RET);
            *(dword_t*)((mem_t)detour_buffer + sizeof(DETOUR_PUSH)) = (dword_t)dst;
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }
        break;

        case DETOUR_METHOD4:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_DETOUR_MOVABS_RAX, _DETOUR_QWORD, _DETOUR_CALL_RAX);
            *(qword_t*)((mem_t)detour_buffer + sizeof(DETOUR_MOVABS_RAX)) = (qword_t)dst;
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }
        break;

        case DETOUR_METHOD5:
        {
            byte_t detour_buffer[] = ASM_GENERATE(_DETOUR_CALL, _DETOUR_DWORD);
            *(dword_t*)((mem_t)detour_buffer + sizeof(DETOUR_CALL)) = (dword_t)((mem_t)dst - (mem_t)src - detour_size);
            memcpy(src, detour_buffer, sizeof(detour_buffer));
        }
        break;
#       endif
    }

    return 0;
}

addr_t DetourTrampoline(addr_t src, addr_t dst, size_t size, int method)
{
    int detour_size = DetourLength(method);
    if(detour_size == BAD_RETURN || size < detour_size || DetourProtect(src, size, DETOUR_PROT_EXEC_READWRITE) != 0) return BAD_RETURN;

#   if defined(DETOUR_86)
    byte_t gateway_buffer[] = ASM_GENERATE(_DETOUR_MOV_EAX, _DETOUR_DWORD, _DETOUR_JMP_EAX);
    *(dword_t*)((mem_t)gateway_buffer + sizeof(DETOUR_MOV_EAX)) = src + size;
#   elif defined(DETOUR_64)
    byte_t gateway_buffer[] = ASM_GENERATE(_DETOUR_MOVABS_RAX, _DETOUR_QWORD, _DETOUR_JMP_RAX);
    *(qword_t*)((mem_t)gateway_buffer + sizeof(DETOUR_MOVABS_RAX)) = src + size;
#   endif

    size_t gateway_size = size + sizeof(gateway_buffer);
    addr_t gateway = DetourAllocate(gateway_size, DETOUR_PROT_EXEC_READWRITE);
    if(!gateway || gateway == -1) return BAD_RETURN;
    memset(gateway, 0x90, gateway_size);
    memcpy(gateway, src, size);
    memcpy((addr_t)((mem_t)gateway + size), gateway_buffer, sizeof(gateway_buffer));
    DetourProtect(gateway, gateway_size, DETOUR_PROT_EXEC | DETOUR_PROT_READ);

    Detour(src, dst, size, method);

    return gateway;
}

#endif