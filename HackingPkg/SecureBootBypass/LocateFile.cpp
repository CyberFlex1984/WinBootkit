#include "LocateFile.hpp"

EFI_STATUS Boot::LocateFile(CHAR16* ImagePath, EFI_DEVICE_PATH* &DevicePath){
    DevicePath = nullptr;

    UINTN NumHandles;
	EFI_HANDLE* Handles;
    EFI_STATUS status = gBS->LocateHandleBuffer(ByProtocol,&gEfiSimpleFileSystemProtocolGuid,NULL,&NumHandles,&Handles);

    if(EFI_ERROR(status)){
        return status;
    }

    for(UINTN i = 0; i < NumHandles; ++i){ // ++i cause I'm cool boy
        EFI_FILE_IO_INTERFACE *IoDevice;
        status = gBS->OpenProtocol(Handles[i],
                                    &gEfiSimpleFileSystemProtocolGuid,
                                    (void**)&IoDevice,
                                    gImageHandle,
                                    NULL,
                                    EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        
        if(status != EFI_SUCCESS) continue; //Maybe SimpleFileSystemProtocol don't know about NTFS, EXT3, EXT4, BTRFS and etc...
        
        EFI_FILE_HANDLE VolumeHandle;
        status = IoDevice->OpenVolume(IoDevice,&VolumeHandle);
        
        if(status != EFI_SUCCESS) continue; // Okay, maybe the same problems

        EFI_FILE_HANDLE FileHandle;
        status = VolumeHandle->Open(VolumeHandle,
                                    &FileHandle,
                                    ImagePath,
                                    EFI_FILE_MODE_READ,
                                    EFI_FILE_READ_ONLY);
        if(!EFI_ERROR(status)){
            FileHandle->Close(FileHandle);
            VolumeHandle->Close(VolumeHandle);
            DevicePath = FileDevicePath(Handles[i],ImagePath);

            break; //we found file!
        }

        VolumeHandle->Close(VolumeHandle); //closing volume handle
    }

    FreePool((void*)Handles); //no memory leak, yeah, Rust?

    return status;
}