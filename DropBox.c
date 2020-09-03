#include <fltkernel.h>
#include <dontuse.h>
#include <wdm.h>

#define MAX_FILE_NAME_SIZE 500

PFLT_FILTER FilterHandle = NULL;

//----------------------------------------------
//---------------Declarations-------------------
//----------------------------------------------

//
// DriverEntry routine
//

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(
	PDRIVER_OBJECT	DriverObject,
	PUNICODE_STRING	RegistryPath
);

//
// Driver unload routine
//

NTSTATUS DriverUnload(
	FLT_FILTER_UNLOAD_FLAGS Flags
);

//
// IRP_MJ_CREATE preoperation callback
//

FLT_PREOP_CALLBACK_STATUS PreCreate(
	PFLT_CALLBACK_DATA		Data,
	PCFLT_RELATED_OBJECTS	RelatedObjects,
	PVOID*					CompletionContext
);


FLT_PREOP_CALLBACK_STATUS PreRead(
	PFLT_CALLBACK_DATA		Data,
	PCFLT_RELATED_OBJECTS	RelatedObjects,
	PVOID*					CompletionContext
);

//
// IRP_MJ_WRITE preoperation callback
//

FLT_PREOP_CALLBACK_STATUS PreWrite(
	PFLT_CALLBACK_DATA		Data,
	PCFLT_RELATED_OBJECTS	RelatedObjects,
	PVOID*					CompletionContext
);

//
// Useless routine printing file name
//

NTSTATUS PrintFileName(
	PFLT_CALLBACK_DATA Data
);

//
// Filter operation registration data
//


CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{IRP_MJ_CREATE,
	0,
	PreCreate,
	NULL},

	{IRP_MJ_WRITE,
	0,
	PreWrite,
	NULL},
	
	{IRP_MJ_OPERATION_END}
};


//
// Filter registration data
//

CONST FLT_REGISTRATION Registration = {
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	0,

	NULL,
	Callbacks,

	DriverUnload,

	NULL,
	NULL,
	NULL,

	NULL,
	NULL,
	NULL,
	NULL
};

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#endif

//
// DriverEntry routine
//

NTSTATUS DriverEntry(
	PDRIVER_OBJECT	DriverObject,
	PUNICODE_STRING	RegistryPath
) {
	UNREFERENCED_PARAMETER(RegistryPath);

	//
	// Registating filter
	//

	NTSTATUS status = FltRegisterFilter(
		DriverObject, 
		&Registration, 
		&FilterHandle
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Filter registration failed!\r\n");

		return status;
	}

	DbgPrint("Registered!\r\n");

	status = FltStartFiltering(FilterHandle);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Filtering not started!\r\n");

		FltUnregisterFilter(FilterHandle);

		return status;
	}

	DbgPrint("Loaded!\r\n");

	return STATUS_SUCCESS;
}

//
// Driver unload function
//

NTSTATUS DriverUnload(
	FLT_FILTER_UNLOAD_FLAGS Flags
) {
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();
	
	FltUnregisterFilter(FilterHandle);

	DbgPrint("Unloaded!\r\n");

	return STATUS_SUCCESS;
}

//
// Preoperation callback
//

FLT_PREOP_CALLBACK_STATUS PreCreate(
	PFLT_CALLBACK_DATA		Data,
	PCFLT_RELATED_OBJECTS	RelatedObjects,
	PVOID*					CompletionContext
) {
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE			   FileHandle = NULL;
	IO_STATUS_BLOCK    IoStatusBlock = {};
	PFLT_FILE_NAME_INFORMATION FileNameInformation = NULL;
	WCHAR			   FileName[MAX_FILE_NAME_SIZE] = { 0 };
	UNICODE_STRING     SyncName;
	OBJECT_ATTRIBUTES  ObjectAttributes;

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(RelatedObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	

	//
	// Getting file name information
	//

	status = FltGetFileNameInformation(
		Data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
		&FileNameInformation
	);

	if (NT_SUCCESS(status)) {
		status = FltParseFileNameInformation(FileNameInformation);

		if (NT_SUCCESS(status) && FileNameInformation->Name.MaximumLength < MAX_FILE_NAME_SIZE) {
			//
			// Copying file name to memory
			//
			RtlCopyMemory(FileName, FileNameInformation->Name.Buffer, FileNameInformation->Name.MaximumLength);
			
			if (wcsstr(FileName, L"\\Device\\HarddiskVolume2\\FolderOne\\") != NULL) {
				DbgPrint("Ñreate to be done!\n");
				WCHAR Name[MAX_FILE_NAME_SIZE] = L"\\DosDevices\\C:\\FolderTwo\\";
				wcscpy(&Name[25], &FileName[34]);

				DbgPrint("NAME: %ws\n", Name);
				RtlInitUnicodeString(&SyncName, Name);

				InitializeObjectAttributes(
					&ObjectAttributes, 
					&SyncName,
					OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
					NULL, 
					NULL
				);

				

				//
				// Check if IRQL = 0
				//

				if (KeGetCurrentIrql() != PASSIVE_LEVEL)
					return STATUS_INVALID_DEVICE_STATE;
				//
				// Creating file if it does not exist in Folder 2
				//

				status = ZwCreateFile(
					&FileHandle,
					GENERIC_WRITE,
					&ObjectAttributes, 
					&IoStatusBlock, 
					NULL,
					FILE_ATTRIBUTE_NORMAL,
					0,
					FILE_CREATE,
					FILE_SYNCHRONOUS_IO_NONALERT,
					NULL, 
					0
				);

				if (NT_SUCCESS(status) && NT_SUCCESS(IoStatusBlock.Information))
					ZwClose(FileHandle);
			}
		}

		FltReleaseFileNameInformation(FileNameInformation);
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}





FLT_PREOP_CALLBACK_STATUS PreWrite(
	PFLT_CALLBACK_DATA		Data,
	PCFLT_RELATED_OBJECTS	RelatedObjects,
	PVOID*					CompletionContext
) {
	PFLT_FILE_NAME_INFORMATION FileNameInformation = NULL;
	WCHAR FileName[MAX_FILE_NAME_SIZE] = { 0 };
	UNICODE_STRING     uniName = {};
	OBJECT_ATTRIBUTES  objAttr = {};
	HANDLE			   handle = 0;
	IO_STATUS_BLOCK    ioStatusBlock;
	WCHAR Name[MAX_FILE_NAME_SIZE] = L"\\DosDevices\\C:\\FolderTwo\\";

	UNREFERENCED_PARAMETER(RelatedObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	NTSTATUS status = FltGetFileNameInformation(
		Data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
		&FileNameInformation
	);

	if (NT_SUCCESS(status)) {
		status = FltParseFileNameInformation(FileNameInformation);

		if (NT_SUCCESS(status) && FileNameInformation->Name.MaximumLength < MAX_FILE_NAME_SIZE) {
			RtlCopyMemory(FileName, FileNameInformation->Name.Buffer, FileNameInformation->Name.MaximumLength);

			if (wcsstr(FileName, L"\\Device\\HarddiskVolume2\\FolderOne\\") != NULL)
				DbgPrint("Write to be done!\n");

			wcscpy(&Name[25], &FileName[34]);

			DbgPrint("NAME: %ws\n", Name);
			
			RtlInitUnicodeString(&uniName, Name);
			
			InitializeObjectAttributes(
				&objAttr, &uniName,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				NULL, 
				NULL
			);

			//
			// Check IRQL
			//

			if (KeGetCurrentIrql() != PASSIVE_LEVEL)
				return STATUS_INVALID_DEVICE_STATE;

			status = ZwCreateFile(&handle,
				GENERIC_WRITE,
				&objAttr, &ioStatusBlock, NULL,
				FILE_ATTRIBUTE_NORMAL,
				0,
				FILE_OPEN_IF,
				FILE_SYNCHRONOUS_IO_NONALERT,
				NULL, 0);

			
			

			if (NT_SUCCESS(status)) {
				LARGE_INTEGER Offset = Data->Iopb->Parameters.Write.ByteOffset;
				ULONG BufferLength = Data->Iopb->Parameters.Write.Length;
				PVOID Buffer = MmAllocateNonCachedMemory(BufferLength);
				
				//
				// Copy data to buffer
				//

				RtlCopyMemory(
					Buffer, 
					Data->Iopb->Parameters.Write.WriteBuffer, 
					BufferLength
				);

				//
				// Write to file
				//

				status = ZwWriteFile(
					handle, 
					0, 
					NULL, 
					NULL, 
					&ioStatusBlock, 
					Buffer, 
					BufferLength, 
					&Offset, 
					NULL
				);

				if (NT_SUCCESS(status))
					DbgPrint("WRITTEN!\n");

				//
				// Free buffer we do not need anymore
				//

				MmFreeNonCachedMemory(
					Buffer, 
					BufferLength
				);

				ZwClose(handle);
			}
		
		}

		FltReleaseFileNameInformation(FileNameInformation);
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


NTSTATUS PrintFileName(
	PFLT_CALLBACK_DATA Data
) {
	PFLT_FILE_NAME_INFORMATION FileNameInformation = NULL;
	WCHAR FileName[MAX_FILE_NAME_SIZE] = { 0 };

	NTSTATUS status = FltGetFileNameInformation(
		Data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
		&FileNameInformation
	);

	if (NT_SUCCESS(status)) {
		status = FltParseFileNameInformation(FileNameInformation);

		if (NT_SUCCESS(status) && FileNameInformation->Name.MaximumLength < MAX_FILE_NAME_SIZE) {
			RtlCopyMemory(FileName, FileNameInformation->Name.Buffer, FileNameInformation->Name.MaximumLength);

			KdPrint(("%ws\r\n", FileName));
		}

		FltReleaseFileNameInformation(FileNameInformation);
	}

	return status;
}