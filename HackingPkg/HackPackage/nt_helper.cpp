#include "nt_helper.hpp"


EFI_IMAGE_DOS_HEADER* NtHelper::GetDosHeader(void* addr){
    EFI_IMAGE_DOS_HEADER* dos_header = (EFI_IMAGE_DOS_HEADER*)addr;
    if(dos_header->e_magic == EFI_IMAGE_DOS_SIGNATURE) return dos_header;

    dos_header = (EFI_IMAGE_DOS_HEADER*)((UINT64)dos_header  &~ ( 0x1000 - 1 ));
    while(dos_header){
        if(dos_header->e_magic == EFI_IMAGE_DOS_SIGNATURE){
            return dos_header;
        }
        dos_header = (EFI_IMAGE_DOS_HEADER*)((UINT64)dos_header - 0x1000);
    }

    return nullptr;
}

EFI_IMAGE_NT_HEADERS64* NtHelper::GetNtHeader(void* addr){
    auto dos_header = GetDosHeader(addr);
    if(!dos_header) return nullptr;
    EFI_IMAGE_NT_HEADERS64* nt_header = (EFI_IMAGE_NT_HEADERS64*)((UINT64)dos_header + dos_header->e_lfanew);
    if(nt_header->Signature != EFI_IMAGE_NT_SIGNATURE) return nullptr;
    return nt_header;
}

EFI_IMAGE_SECTION_HEADER* NtHelper::GetFirstSectionHeader(void* addr){
    auto nt_header = GetNtHeader(addr);
    if(!nt_header) return nullptr;
    EFI_IMAGE_SECTION_HEADER* Section = (EFI_IMAGE_SECTION_HEADER*)((UINT64)nt_header + sizeof(nt_header->Signature) + sizeof(nt_header->FileHeader) + nt_header->FileHeader.SizeOfOptionalHeader);
    return Section;
}

EFI_IMAGE_SECTION_HEADER* NtHelper::GetSectionHeaderByName(void* addr, const char* name){
    auto nt_header = GetNtHeader(addr);
    if(!nt_header) return nullptr;
    auto Section = GetFirstSectionHeader(addr);
    if(!Section) return nullptr;

    auto str_contains = [](const char* str1, const char* str2){
        for(UINT64 i = 0; str1[i]; ++i){
            if(str1[i] != str2[i]) return false;
        }
        return true;
    };

    for(UINT16 i = 0; i < nt_header->FileHeader.NumberOfSections; ++i){
        if(str_contains(name,(char*)Section[i].Name)){
            return Section + i;
        }
    }

    return nullptr;
}

void* NtHelper::GetBeginSectionByName(void* addr, const char* name){
    auto dos_header = GetDosHeader(addr);
    if(!dos_header) return nullptr;
    auto Section = GetSectionHeaderByName(addr,name);
    if(!Section) return nullptr;

    return (void*)((UINT64)dos_header + Section->VirtualAddress);
}
void* NtHelper::GetEndSectionByName(void* addr, const char* name){
    auto dos_header = GetDosHeader(addr);
    if(!dos_header) return nullptr;
    auto Section = GetSectionHeaderByName(addr,name);
    if(!Section) return nullptr;

    return (void*)((UINT64)dos_header + Section->VirtualAddress + Section->SizeOfRawData);
}