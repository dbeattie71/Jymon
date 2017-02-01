/*++

Module Name:

	JyMon.c

Abstract:

	This is the main module of the JyMon miniFilter driver.

Environment:

	Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;

#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*
* @brief    Structure that contains all the global data structures
*           used throughout this monitor.
*/
typedef struct _JYMON_DATA
{

	PDRIVER_OBJECT DriverObject; //  The object that identifies this driver.
	PFLT_FILTER FilterHandle; //  The filter handle that results from a call to FltRegisterFilter.
	PEPROCESS UserProcess; 	//  User process that connected to the port
	PFLT_PORT ServerPort; //  Listens for incoming connections
	PFLT_PORT ClientPort; 	//  Client port for a connection to user-mode

} JYMON_DATA, *PJYMON_DATA;

typedef struct _JYMON_STREAMHANDLE_CONTEXT
{

	BOOLEAN RescanRequired;

} JYMON_STREAMHANDLE_CONTEXT, *PJYMON_STREAMHANDLE_CONTEXT;

#define READ_BUFFER_SIZE 1024
typedef struct _JYMON_NOTIFICATION
{

	//UCHAR ProcessName[READ_BUFFER_SIZE];
	//	ULONG ProcessId;
	UCHAR MajorFunction;
	ULONG BytesToScan;
	ULONG Reserved;
	ULONG Contents[READ_BUFFER_SIZE];

} JYMON_NOTIFICATION, *PJYMON_NOTIFICATION;

typedef struct _JYMON_REPLY
{

	ULONG Reserved;

} JYMON_REPLY, *PJYMON_REPLY;

ULONG SectorSize = 0;
JYMON_DATA JyMonData;


PVOID AllocateMemory(SIZE_T Size, ULONG Tag)
{
	POOL_TYPE PoolType;
	if (KeGetCurrentIrql() <= DISPATCH_LEVEL)
	{
		PoolType = NonPagedPool;
	}
	else
	{
		PoolType = PagedPool;
	}

	return ExAllocatePool(PoolType, Size);
}

void FreeMemory(void *_Memory)
{
	ExFreePool(_Memory);
}


NTSTATUS
JyMonGetSectorSize(
	_In_ PFLT_INSTANCE Instance,
	_Out_ PULONG SectorSize
	)
{

	NTSTATUS Status;
	PFLT_VOLUME Volume = NULL;
	FLT_VOLUME_PROPERTIES VolumeProperties;
	ULONG Length = 0;

	__try
	{
		Status = FltGetVolumeFromInstance(Instance, &Volume);
		if (!NT_SUCCESS(Status))
		{
			__leave;
		}

		//
		//  Determine sector size. Noncached I/O can only be done at sector size offsets, and in lengths which are
		//  multiples of sector size. A more efficient way is to make this call once and remember the sector size in the
		//  instance setup routine and setup an instance context where we can cache it.
		//

		Status = FltGetVolumeProperties(Volume,
			&VolumeProperties,
			sizeof(FLT_VOLUME_PROPERTIES),
			&Length);

		//
		//  STATUS_BUFFER_OVERFLOW can be returned - however we only need the properties, not the names
		//  hence we only check for error status.
		//

		if (NT_ERROR(Status))
		{
			__leave;
		}
		*SectorSize = max(READ_BUFFER_SIZE, VolumeProperties.SectorSize);
	}
	__finally
	{
		if (NULL != Volume)
		{
			FltObjectDereference(Volume);
		}
	}

	return Status;
}

NTSTATUS
JyMonNotifyEventRow(
	_Inout_ PFLT_CALLBACK_DATA CallbackData,
	_In_ PCFLT_RELATED_OBJECTS FltObjects
	)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PJYMON_NOTIFICATION Notification = NULL;
	JYMON_REPLY Reply;
	PVOID Buffer = NULL;
	ULONG BytesRead;
	ULONG ReplyLength;
	LARGE_INTEGER Offset;
	PFLT_FILE_NAME_INFORMATION FileNameInformation;
	PFLT_IO_PARAMETER_BLOCK Iopb = CallbackData->Iopb;

	KIRQL CurrentIrql = KeGetCurrentIrql();
	if (APC_LEVEL < CurrentIrql)
	{
		Status = STATUS_UNSUCCESSFUL;
		return Status;
	}

	if (NULL == FltObjects->FileObject ||
		NULL == CallbackData ||
		0 == FltObjects->FileObject->FileName.Length ||
		0 == FltObjects->FileObject->FileName.MaximumLength ||
		NULL == FltObjects->FileObject->FileName.Buffer)
	{
		Status = STATUS_UNSUCCESSFUL;
		return Status;
	}

	//
	// The TopLevelIrp parameter that you can retrieve by calling IoGetTopLevelIrp 
	// indicates where the present call originated.
	// If it has originated from a user space call, then there is no TopLevelIrp 
	// component and this value is NULL.
	// If it has originated from the cache, then the top level Irp is actually 
	// a constant FSRTL_CACHE_TOP_LEVEL_IRP.This can happen on the write path, when the Cache is actually doing a WriteBehind for a modified file.
	// If it has originated from the modified page writer in the Cache, then 
	// the value is FSRTL_MOD_WRITE_TOP_LEVEL_IRP.
	// If the file system itself is the top level component as in a recursive call (got this a couple of times when you try to open a file with 
	// notepad), the value is FSRTL_FSP_TOP_LEVEL_IRP.
	// If it is the result of a FAST CALL(got this once when I tried to open a log
	// file with Wordpad), the value is FSRTL_FAST_IO_TOP_LEVEL_IRP
	//
	if (NULL == IoGetTopLevelIrp())
	{
		Status = FltGetFileNameInformation(CallbackData,
			FLT_FILE_NAME_NORMALIZED |
			FLT_FILE_NAME_QUERY_DEFAULT,
			&FileNameInformation);

		if (!NT_SUCCESS(Status))
		{
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		FltParseFileNameInformation(FileNameInformation);
		__try
		{
			Notification->BytesToScan = min(FileNameInformation->Name.Length, READ_BUFFER_SIZE);
			RtlCopyMemory(&Notification->Contents,
				FileNameInformation->Name.Buffer,
				Notification->BytesToScan);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			CallbackData->IoStatus.Status = GetExceptionCode();
			CallbackData->IoStatus.Information = 0;
			Status = FLT_PREOP_COMPLETE;
		}

		FltReleaseFileNameInformation(FileNameInformation);
	}

	Notification->MajorFunction = Iopb->MajorFunction;

	if (0 >= SectorSize)
	{
		Status = JyMonGetSectorSize(FltObjects->Instance, &SectorSize);
		if (!NT_SUCCESS(Status))
		{
			goto CleanupNotifyEventRow;
		}
	}

	__try
	{
		Buffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance,
			NonPagedPool,
			SectorSize,
			'nacS');
		if (NULL == Buffer)
		{
			Status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		Notification = (PJYMON_NOTIFICATION)ExAllocatePoolWithTag(NonPagedPool,
			sizeof(JYMON_NOTIFICATION),
			'nacS');
		if (NULL == Notification)
		{
			Status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		//
		//  Read the beginning of the file and pass the contents to user mode.
		//

		Offset.QuadPart = BytesRead = 0;
		Status = FltReadFile(FltObjects->Instance,
			FltObjects->FileObject,
			&Offset,
			SectorSize,
			Buffer,
			FLTFL_IO_OPERATION_NON_CACHED |
			FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
			&BytesRead,
			NULL,
			NULL);

		if (NT_SUCCESS(Status) && (0 != BytesRead))
		{
			Notification->BytesToScan = (ULONG)BytesRead;

			//
			//  Copy only as much as the buffer can hold
			//

			RtlCopyMemory(&Notification->Contents,
				Buffer,
				min(Notification->BytesToScan, READ_BUFFER_SIZE));

			ReplyLength = sizeof(JYMON_REPLY);

			Status = FltSendMessage(JyMonData.FilterHandle,
				&JyMonData.ClientPort,
				Notification,
				sizeof(JYMON_NOTIFICATION),
				&Reply,
				&ReplyLength,
				NULL);

			if (NT_SUCCESS(Status))
			{
				DbgPrint("!!! JyMon.sys --- successed on sending message to user-mode.");
			}
			else
			{
				DbgPrint("!!! scanner.sys --- couldn't send message to user-mode to scan file, status 0x%X\n", Status);
			}
		}
	}
	__finally
	{
		if (NULL != Buffer)
		{
			FltFreePoolAlignedWithTag(FltObjects->Instance, Buffer, 'nacS');
		}
		if (NULL != Notification)
		{
			ExFreePoolWithTag(Notification, 'nacS');
		}
	}

CleanupNotifyEventRow:
	return Status;
}

/*************************************************************************
	Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry
(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
	);

NTSTATUS
JyMonUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
	);

NTSTATUS
JyMonInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
	);

NTSTATUS
JyMonInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS
JyMonPreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS
JyMonPostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	);

NTSTATUS
ScannerPortConnect(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID *ConnectionCookie
	);

VOID
ScannerPortDisconnect(
	_In_opt_ PVOID ConnectionCookie
	);

}

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, JyMonUnload)
#pragma alloc_text(PAGE, JyMonInstanceQueryTeardown)
#pragma alloc_text(PAGE, JyMonInstanceSetup)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE,
	0,
	(PFLT_PRE_OPERATION_CALLBACK)JyMonPreCreate,
	(PFLT_POST_OPERATION_CALLBACK)JyMonPostCreate },

	{ IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

	{ FLT_STREAMHANDLE_CONTEXT,
	0,
	NULL,
	sizeof(JYMON_STREAMHANDLE_CONTEXT),
	'chBS' },

	{ FLT_CONTEXT_END }

};

CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,         //  Version
	0,                                //  Flags

	ContextRegistration,              //  Context
	Callbacks,                        //  Operation callbacks

	(PFLT_FILTER_UNLOAD_CALLBACK)JyMonUnload,                      //  MiniFilterUnload

	(PFLT_INSTANCE_SETUP_CALLBACK)JyMonInstanceSetup,               //  InstanceSetup
	(PFLT_INSTANCE_QUERY_TEARDOWN_CALLBACK)JyMonInstanceQueryTeardown,       //  InstanceQueryTeardown
	NULL,                             //  InstanceTeardownStart
	NULL,                             //  InstanceTeardownComplete

	NULL,                             //  GenerateFileName
	NULL,                             //  GenerateDestinationFileName
	NULL                              //  NormalizeNameComponent

};


/*
* @brief    This routine is called by the filter manager when a new instance is created.
*           We specified in the registry that we only want for manual attachments,
*           so that is all we should receive here.
*
* @param    FltObjects - Describes the instance and volume which we are being asked to setup.
* @param    Flags - Flags describing the type of attachment this is.
* @param    VolumeDeviceType - The DEVICE_TYPE for the volume to which this instance
*           will attach.
* @param    VolumeFileSystemType - The file system formatted on this volume.
*
* @return   STATUS_SUCCESS            - we wish to attach to the volume
* @return   STATUS_FLT_DO_NOT_ATTACH  - no, thank you
*/
NTSTATUS
JyMonInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
	)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	FLT_ASSERT(FltObjects->Filter == JyMonData.FilterHandle);

	//
	//  Don't attach to network volumes.
	//

	if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {

		return STATUS_FLT_DO_NOT_ATTACH;
	}

	return STATUS_SUCCESS;
}


/*
* @brief    This is called when an instance is being manually deleted by a
*           call to FltDetachVolume or FilterDetach thereby giving us a
*           chance to fail that detach request.
*      
*           If this routine is not defined in the registration structure, explicit
*           detach requests via FltDetachVolume or FilterDetach will always be
*           failed.
*
* @param    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
*           opaque handles to this filter, instance and its associated volume.
* @param    Flags - Indicating where this detach request came from.
*
* @return   STATUS_SUCCESS - we allow instance detach to happen
*/
NTSTATUS
JyMonInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
	)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("JyMon!JyMonInstanceQueryTeardown: Entered\n"));

	return STATUS_SUCCESS;
}


/*************************************************************************
	MiniFilter initialization and unload routines.
*************************************************************************/

/*
* @brief    This is the initialization routine for this miniFilter driver.  This
*           registers with FltMgr and initializes all global data structures.
*
* @param    DriverObject - Pointer to driver object created by the system to
*           represent this driver.
* @param    RegistryPath - Unicode string identifying where the parameters for this
*           driver are located in the registry.
*
* @return   Returns STATUS_SUCCESS.
*/
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
	)
{
	NTSTATUS Status;

	UNREFERENCED_PARAMETER(RegistryPath);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("JyMon!DriverEntry: Entered\n"));

	//
	//  Register with FltMgr to tell it our callback routines
	//

	Status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&JyMonData.FilterHandle);

	FLT_ASSERT(NT_SUCCESS(Status));

	if (NT_SUCCESS(Status)) 
	{
		//
		//  Start filtering i/o
		//
		Status = FltStartFiltering(JyMonData.FilterHandle);
		if (!NT_SUCCESS(Status)) 
		{
			FltUnregisterFilter(JyMonData.FilterHandle);
		}
	}

	return Status;
}

NTSTATUS
JyMonUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
	)
	/*++

	Routine Description:

		This is the unload routine for this miniFilter driver. This is called
		when the minifilter is about to be unloaded. We can fail this unload
		request if this is not a mandatory unload indicated by the Flags
		parameter.

	Arguments:

		Flags - Indicating if this is a mandatory unload.

	Return Value:

		Returns STATUS_SUCCESS.

	--*/
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("JyMon!JyMonUnload: Entered\n"));

	FltUnregisterFilter(JyMonData.FilterHandle);

	return STATUS_SUCCESS;
}


/*************************************************************************
	MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
JyMonPreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
	)
	/*++

	Routine Description:

		This routine is a pre-operation dispatch routine for this miniFilter.

		This is non-pageable because it could be called on the paging path

	Arguments:

		Data - Pointer to the filter callbackData that is passed to us.

		FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
			opaque handles to this filter, instance, its associated volume and
			file object.

		CompletionContext - The context for the completion routine for this
			operation.

	Return Value:

		The return value is the status of the operation.

	--*/
{
	NTSTATUS status;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("JyMon!JyMonPreOperation: Entered\n"));


	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

/*
* @brief    Post create callback.
*
* @param    Data - The structure which describes the operation parameters.
* @param    FltObject - The structure which describes the objects affected by this
*           operation.
* @param    CompletionContext - The operation context passed fron the pre-create
*           callback.
* @param    Flags - Flags to say why we are getting this post-operation callback.
*
* @return   FLT_POSTOP_FINISHED_PROCESSING - ok to open the file or we wish to deny
*           access to this file, hence undo the open
*/
FLT_POSTOP_CALLBACK_STATUS
JyMonPostCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
	)
{
	PJYMON_STREAMHANDLE_CONTEXT JyMonContext = NULL;
	PFLT_FILE_NAME_INFORMATION FileNameInformation;
	NTSTATUS Status;

	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("JyMon!JyMonPostOperation: Entered\n"));

	
	JyMonNotifyEventRow(Data, FltObjects);

	return FLT_POSTOP_FINISHED_PROCESSING;
}
