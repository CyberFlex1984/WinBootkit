#include <ntddk.h>

__declspec(dllexport) volatile UCHAR MapperData[21] = { 0 };
BOOLEAN MemCopyWP(UCHAR * dst, UCHAR * src, ULONG size)
{
    PMDL Mdl = NULL;
    PVOID Mapped = NULL;

    Mdl = IoAllocateMdl(dst, size, FALSE, FALSE, NULL);
    if (!Mdl)
    {
        return FALSE;
    }

    MmProbeAndLockPages(Mdl, KernelMode, IoModifyAccess);

    Mapped = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, 0, HighPagePriority);
    if (!Mapped)
    {
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return FALSE;
    }

    // memcpy(mapped, src, size);  // movups  xmmword ptr [rcx],xmm0
    for (unsigned int i = 0; i < size; i++)
    {
        *((UCHAR*)Mapped + i) = *(src + i);
    }

    MmUnmapLockedPages(Mapped, Mdl);
    MmUnlockPages(Mdl);
    IoFreeMdl(Mdl);

    return TRUE;
}

NTSTATUS DriverEntry(struct _DRIVER_OBJECT * DriverObject, PUNICODE_STRING RegistryPath, PDRIVER_INITIALIZE EntryPointOfTargetModule)
{
    MemCopyWP((UCHAR*)EntryPointOfTargetModule, (UCHAR*)MapperData, sizeof(MapperData)); //unhook

    (void)DriverObject;
    (void)RegistryPath;

    return EntryPointOfTargetModule(DriverObject,RegistryPath); //returning to original driver
}

VOID DriverUnload(struct _DRIVER_OBJECT * DriverObject)
{
    (void)DriverObject;
}
