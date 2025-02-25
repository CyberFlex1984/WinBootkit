#include "SetServicePointer.hpp"

#define CR0_WP ((UINTN)0x00010000)    // CR0.WP
#define CR0_PG ((UINTN)0x80000000)    // CR0.PG
#define CR4_CET ((UINTN)0x00800000)   // CR4.CET
#define CR4_LA57 ((UINTN)0x00001000)  // CR4.LA57
#define MSR_EFER ((UINTN)0xC0000080)  // Extended Function Enable Register
#define EFER_LMA ((UINTN)0x00000400)  // Long Mode Active
#define EFER_UAIE ((UINTN)0x00100000) // Upper Address Ignore Enabled

void *Boot::SetServicePointer(EFI_TABLE_HEADER *ServiceTableHeader, void **ServiceTableFunction, void *newFunction)
{
    EFI_TPL Tpl;

    if(gBS && gBS->RaiseTPL && gBS->RestoreTPL && gBS->CalculateCrc32 && ServiceTableHeader){
        Tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);
    }

    const UINTN Cr0 = AsmReadCr0();
    const BOOLEAN WpSet = (Cr0 & CR0_WP) != 0;
    if (WpSet){
        AsmWriteCr0(Cr0 & ~CR0_WP);
    }

    void *orig_func = *ServiceTableFunction;
    *ServiceTableFunction = newFunction;

    if(gBS && gBS->RaiseTPL && gBS->RestoreTPL && gBS->CalculateCrc32 && ServiceTableHeader){
        ServiceTableHeader->CRC32 = 0;
        gBS->CalculateCrc32(ServiceTableHeader, ServiceTableHeader->HeaderSize, &ServiceTableHeader->CRC32);
    }

    if (WpSet){
        AsmWriteCr0(Cr0);
    }

    if(gBS && gBS->RaiseTPL && gBS->RestoreTPL && gBS->CalculateCrc32 && ServiceTableHeader){
        gBS->RestoreTPL(Tpl);
    }

    return orig_func;
}