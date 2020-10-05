/*++

Module Name:

    HardLink.c

Abstract:

    This is the main module of the HardLink miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;
#define MAX_FILE_NAME_SIZE 1000



/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);


NTSTATUS
HardLinkUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
HardLinkInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS PreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

VOID HardLinkOperationStatusCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
);

FLT_POSTOP_CALLBACK_STATUS PostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);


EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, HardLinkUnload)

#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
    0,
    PreCreate,
    PostCreate},

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    HardLinkUnload,                     //  MiniFilterUnload

    NULL,                               //  InstanceSetup
    NULL,                               //  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};






/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("Loaded!\n");

    status = FltRegisterFilter(DriverObject,
        &FilterRegistration,
        &gFilterHandle);

    FLT_ASSERT(NT_SUCCESS(status));

    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(gFilterHandle);

        if (!NT_SUCCESS(status))
            FltUnregisterFilter(gFilterHandle);

    }

    return status;
}

NTSTATUS
HardLinkUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
) {
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    KdPrint(("Unloaded!\n"));

    FltUnregisterFilter(gFilterHandle);

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS PreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    DbgPrint("Create callback invoked!\r\n");

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



FLT_POSTOP_CALLBACK_STATUS PostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
) {
    NTSTATUS status = STATUS_SUCCESS;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE FileHandle;
    PFLT_FILE_NAME_INFORMATION FileNameInformation;
    WCHAR Name[MAX_FILE_NAME_SIZE] = L"\\DosDevices\\C:\\FolderTwo\\";

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    status = FltGetFileNameInformation(
        Data, 
        FLT_FILE_NAME_NORMALIZED,
        &FileNameInformation
    );

    if (!NT_SUCCESS(status)) {
        goto PostCreateExit;
    }

    status = FltParseFileNameInformation(FileNameInformation);

    if (!NT_SUCCESS(status)) {
        goto PostCreateRelease;
    }

    PWCHAR FileName = ExAllocatePool(NonPagedPool, FileNameInformation->Name.MaximumLength * sizeof(WCHAR));
    RtlCopyMemory(FileName, FileNameInformation->Name.Buffer, FileNameInformation->Name.MaximumLength);

    if (wcsstr(FileName, L"\\Device\\HarddiskVolume2\\FolderOne\\") == NULL) {
        ExFreePool(FileName);

        goto PostCreateRelease;
    }
    
    wcscpy(&Name[25], &FileName[34]);


    status = ObOpenObjectByPointer(
        Data->Iopb->TargetFileObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        0,
        NULL,
        KernelMode,
        &FileHandle
    );
    DbgPrint("New address: %ws %lu\r\n", Name, FileHandle);

    if (!NT_SUCCESS(status)) {
        DbgPrint("Object not opened\r\n");

        ExFreePool(FileName);

        goto PostCreateExit;
    }

    ULONG FileNameLength = wcslen(Name);

    FILE_LINK_INFORMATION FileInformation = {
        TRUE,
        NULL,
        Name,
        FileNameLength
    };

    status = ZwSetInformationFile(
        FileHandle,
        &IoStatusBlock,
        &FileInformation,
        sizeof(FILE_LINK_INFORMATION),
        FileLinkInformation
    );

    if (!NT_SUCCESS(status))
        DbgPrint("HARDLINK NOT CREATED!\r\n");

    status = ZwClose(FileHandle);

    if (!NT_SUCCESS(status))
        DbgPrint("FUCK!\r\n");

PostCreateRelease:
    FltReleaseFileNameInformation(FileNameInformation);

PostCreateExit:

    DbgPrint("Post create callback invoked!\r\n");

    return FLT_POSTOP_FINISHED_PROCESSING;
}