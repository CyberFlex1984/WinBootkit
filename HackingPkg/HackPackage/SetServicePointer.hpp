extern "C" {
    #include <Uefi.h>
    #include <Library/UefiLib.h>
    #include <Library/UefiBootServicesTableLib.h>
    #include <Library/UefiRuntimeServicesTableLib.h>
    #include <Library/DevicePathLib.h>
    #include <Library/MemoryAllocationLib.h>
}

namespace Boot
{
    void* SetServicePointer(EFI_TABLE_HEADER* ServiceTableHeader, void** ServiceTableFunction, void* newFunction);
} // namespace Boot

