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

	UCHAR MajorFunction;

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

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, 
		"JyMon!DriverEntry: Entered\n");

	//
	//  Register with FltMgr to tell it our callback routines
	//
	Status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&JyMonData.FilterHandle);
	if (!NT_SUCCESS(Status)) 
	{
		switch (Status)
		{
			
		case STATUS_INSUFFICIENT_RESOURCES:
			//
			// FltRegisterFilter encountered a pool allocation failure. 
			// This is an error code.
			//
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, 
				"JyMon!DriverEntry!FltRegisterFilter: \
				STATUS_INSUFFICIENT_RESOURCES\n");
			break;

		case STATUS_INVALID_PARAMETER:
			//
			// One of the following :
			//
			// ? The Version member of the Registration structure was not set to 
			// FLT_REGISTRATION_VERSION.
			//
			// ? One of the non - NULL name - provider routines in the Registration 
			// structure was set to an invalid value.The GenerateFileNameCallback,
			// NormalizeNameComponentCallback, and NormalizeNameComponentExCallback 
			// members of FLT_REGISTRATION point to the name - provider routines.
			//
			// STATUS_INVALID_PARAMETER is an error code. 
			//
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, 
				"JyMon!DriverEntry!FltRegisterFilter: \
				STATUS_INVALID_PARAMETER\n");
			break;

		case STATUS_FLT_NOT_INITIALIZED:
			//  
			// The Filter Manager was not initialized when the filter tried to 
			// register. Make sure that the Filter Manager is loaded as a driver.
			// This is an error code.
			//
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, 
				"JyMon!DriverEntry!FltRegisterFilter: \
				STATUS_FLT_NOT_INITIALIZED");
			break;

		case STATUS_OBJECT_NAME_NOT_FOUND:
			//
			// The filter service key is not found in the registry. 
			// (registered service without your own inf file, in my case.)
			// 
			// The filter instance is not registered.
			//
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, 
				"JyMon!DriverEntry!FltRegisterFilter: \
				STATUS_OBJECT_NAME_NOT_FOUND");
		//	goto __START_FILTERING_IO__;
			break;
		}
	}
	else
	{
	//__START_FILTERING_IO__:
		Status = FltStartFiltering(JyMonData.FilterHandle);
		if (!NT_SUCCESS(Status))
		{
			FltUnregisterFilter(JyMonData.FilterHandle);
		}
	}

	return Status = STATUS_SUCCESS;
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
	PJYMON_NOTIFICATION Notification = NULL;
	LARGE_INTEGER Offset;
	ULONG ReplyLength = sizeof(JYMON_REPLY);
	CONST PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;

	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
		"JyMon!JyMonPostOperation: Entered\n");

	__try
	{
		Notification = (PJYMON_NOTIFICATION)FltAllocatePoolAlignedWithTag(FltObjects->Instance,
			NonPagedPool,
			sizeof(JYMON_NOTIFICATION),
			'nacS');
		if (NULL == Notification)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
				"JyMon!JyMonPostOperation : couldn't allocate memory, line %i\n", 
				__LINE__);
			__leave;
		}

		RtlZeroMemory(Notification, sizeof(JYMON_NOTIFICATION));
		Notification->MajorFunction = Iopb->MajorFunction;

		Status = STATUS_SUCCESS;
		Offset.QuadPart = 0;

		Status = FltSendMessage(JyMonData.FilterHandle,
			&JyMonData.ClientPort,
			Notification,
			sizeof(JYMON_NOTIFICATION),
			Notification,
			&ReplyLength,
			NULL);
		if (STATUS_SUCCESS == Status)
		{
			;
		}
		else
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0,
				"JyMon!JyMonPostOperation : Couldn't send message to user-mode, status 0x%X\n",
				Status);
		}
	}
	__finally
	{
		if (NULL != Notification)
		{
			ExFreePoolWithTag(Notification, 'nacS');
		}
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}
