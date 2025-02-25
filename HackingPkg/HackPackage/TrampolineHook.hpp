#pragma once

#include <Zydis/Zydis.h>

namespace Hook
{
    void memcpy(void *dst, void *src, unsigned long size);
    void memset(void *addr, unsigned char byte, unsigned long size);
    void NOP(void *addr, unsigned long size);
    void AbsoluteJMPx64Bytes(void *addr, void *to_jmp_addr);
    ZyanUSize SizeOfHook(void* func_to_be_hooked);
    
    typedef void* (*alloc_fn)(unsigned long size);
    
    void *TrampolineHookX64Alloc(void *func_to_be_hooked, void *your_func, alloc_fn alloc);
    void TrampolineHookX64(void* func_to_be_hooked, void* func, void* original_bytes);
    void TrampolineUnhookX64(void* hooked_func, void* original_bytes);
} // namespace Hook

