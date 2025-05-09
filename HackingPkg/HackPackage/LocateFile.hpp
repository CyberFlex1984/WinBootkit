extern "C" {
    #include <Uefi.h>
    #include <Library/UefiLib.h>
    #include <Library/UefiBootServicesTableLib.h>
    #include <Library/UefiRuntimeServicesTableLib.h>
    #include <Library/DevicePathLib.h>
    #include <Library/MemoryAllocationLib.h>
}

namespace Boot{
    EFI_STATUS LocateFile(CHAR16* ImagePath, EFI_DEVICE_PATH* &DevicePath);
}
