#include "ExitBootServices.hpp"

extern "C" {
    #include <Uefi.h>
    #include <Library/UefiLib.h>
    #include <Library/UefiBootServicesTableLib.h>
    #include <Library/UefiRuntimeServicesTableLib.h>
    #include <Library/DevicePathLib.h>
    #include <Library/MemoryAllocationLib.h>
    #include <Library/PeCoffLib.h>
}

#include "SetServicePointer.hpp"
#include "PatternScan.hpp"
#include "OslArchTransferToKernel.hpp"
#include "nt_helper.hpp"

const char OslArchTransferToKernelSig[] = "\x33\xF6\x4C\x8B\xE1\x4C\x8B\xEA\x0F\x09\x48\x2B\xC0\x66\x8E\xD0\x48\x8B\x25????\x48\x8D\x05????\x48\x8D\x0D????\x0F\x01\x10\x0F\x01\x19";

EFI_EXIT_BOOT_SERVICES orig_ExitBootServices;

EFI_STATUS EFIAPI hk_ExitBootServices(EFI_HANDLE ImageHandle, UINTN MapKey)
{
    gST->ConOut->SetAttribute(gST->ConOut,EFI_GREEN);
    gST->ConOut->ClearScreen(gST->ConOut);
    Print((CHAR16*)L"Unhooking ExitBootServices...\n");
    Boot::SetServicePointer(&gBS->Hdr,(void**)&gBS->ExitBootServices,(void*)orig_ExitBootServices);

    void* addr = __builtin_extract_return_addr(__builtin_return_address(0));
    Print((CHAR16*)L"Address of this caller: %p\n",addr);
    
    auto OslArchTransferToKernel = PatternScan<void*>(  (unsigned char*)NtHelper::GetBeginSectionByName(addr,".text"), 
                                                        (unsigned char*)NtHelper::GetEndSectionByName(addr,".text"), 
                                                        OslArchTransferToKernelSig,
                                                        sizeof(OslArchTransferToKernelSig) - 1);
    if(OslArchTransferToKernel)
    {
        Print((CHAR16*)L"Founded OslArchTransferToKernel at %p\nHooking...\n",OslArchTransferToKernel);
        Runtime::HookOslArchTransferToKernel(OslArchTransferToKernel);
    }
    
    return gBS->ExitBootServices(ImageHandle,MapKey);
}

void Boot::HookExitBootServices()
{
    Print((CHAR16*)L"Hooking ExitBootServices...\n");
    orig_ExitBootServices = (EFI_EXIT_BOOT_SERVICES)SetServicePointer(&gBS->Hdr,(void**)&gBS->ExitBootServices,(void*)&hk_ExitBootServices);
}