#include "TrampolineHook.hpp"

extern "C" {
    #include <Uefi.h>
    #include <Library/UefiLib.h>
    #include <Library/UefiBootServicesTableLib.h>
    #include <Library/UefiRuntimeServicesTableLib.h>
    #include <Library/DevicePathLib.h>
    #include <Library/MemoryAllocationLib.h>
}

#define CR0_WP ((UINTN)0x00010000)    // CR0.WP
#define CR0_PG ((UINTN)0x80000000)    // CR0.PG
#define CR4_CET ((UINTN)0x00800000)   // CR4.CET
#define CR4_LA57 ((UINTN)0x00001000)  // CR4.LA57
#define MSR_EFER ((UINTN)0xC0000080)  // Extended Function Enable Register
#define EFER_LMA ((UINTN)0x00000400)  // Long Mode Active
#define EFER_UAIE ((UINTN)0x00100000) // Upper Address Ignore Enabled

void Hook::TrampolineUnhookX64(void *hooked_func, void *original_bytes)
{
    Hook::memcpy(hooked_func, original_bytes, 14);
}
void Hook::TrampolineHookX64(void *func_to_be_hooked, void *func, void *original_bytes)
{
    if(original_bytes) Hook::memcpy(original_bytes, func_to_be_hooked, 14);
    Hook::AbsoluteJMPx64Bytes(func_to_be_hooked, func);
}

void *Hook::TrampolineHookX64Alloc(void *func_to_be_hooked, void *your_func, alloc_fn alloc)
{
    auto offset = SizeOfHook(func_to_be_hooked);

    auto gateway = alloc(offset + 14);
    if (gateway == nullptr)
    {
        return nullptr;
    }

    {
        Hook::memcpy(gateway, func_to_be_hooked, offset);
        Hook::AbsoluteJMPx64Bytes((void *)((ZyanU64)gateway + offset), (void *)((unsigned char *)func_to_be_hooked + 14));
    }
    Hook::NOP(func_to_be_hooked, offset);
    {
        Hook::AbsoluteJMPx64Bytes(func_to_be_hooked, your_func);
    }
    return gateway;
}

ZyanUSize Hook::SizeOfHook(void *func_to_be_hooked)
{
    ZyanU64 runtime_address = (ZyanU64)func_to_be_hooked;
    // Loop over the instructions in our buffer.
    ZyanUSize offset = 0;
    ZydisDisassembledInstruction instruction;
    while (ZYAN_SUCCESS(ZydisDisassembleIntel(
        /* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
        /* runtime_address: */ runtime_address,
        /* buffer:          */ (unsigned char *)func_to_be_hooked + offset,
        /* length:          */ 0xFFFFF - offset,
        /* instruction:     */ &instruction)))
    {
        if (offset >= 14)
            break;
        offset += instruction.info.length;
        runtime_address += instruction.info.length;
    }
    return offset;
}

void Hook::AbsoluteJMPx64Bytes(void *addr, void *to_jmp_addr)
{
    const UINTN Cr0 = AsmReadCr0();
    const BOOLEAN WpSet = (Cr0 & CR0_WP) != 0;
    if (WpSet){
        AsmWriteCr0(Cr0 & ~CR0_WP); //forgot about mem protection
    }

    *(UINT16*)addr = 0x25FF;
    *(UINT32*)((UINT64)addr + 2) = 0;
    *(UINT64*)((UINT64)addr + 6) = (UINT64)to_jmp_addr;
    /*
        jmp [rip]
        rip: dq to_jmp_addr
    */

    if (WpSet){
        AsmWriteCr0(Cr0);
    }
}

void Hook::NOP(void *addr, unsigned long size) { 
    Hook::memset(addr, 0x90, size); 
}

void Hook::memset(void *addr, unsigned char byte, unsigned long size)
{
    
    const UINTN Cr0 = AsmReadCr0();
    const BOOLEAN WpSet = (Cr0 & CR0_WP) != 0;
    if (WpSet){
        AsmWriteCr0(Cr0 & ~CR0_WP); //forgot about mem protection
    }
    

    for (unsigned long i = 0; i < size; ++i)
    {
        *(unsigned char *)((UINT64)addr + i) = byte;
    }
    
    if (WpSet){
        AsmWriteCr0(Cr0);
    }
    
}
void Hook::memcpy(void *dst, void *src, unsigned long size)
{
    
    const UINTN Cr0 = AsmReadCr0();
    const BOOLEAN WpSet = (Cr0 & CR0_WP) != 0;
    if (WpSet){
        AsmWriteCr0(Cr0 & ~CR0_WP); //forgot about mem protection
    }
    


    for (unsigned long i = 0; i < size; ++i)
    {
        *(unsigned char *)((UINT64)dst + i) = *(unsigned char *)((UINT64)src + i);
    }


    
    if (WpSet){
        AsmWriteCr0(Cr0);
    }
    
}