#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <fltUser.h>
#include <dontuse.h>
#include <share.h>
#include <assert.h>

#define JYMON_READ_BUFFER_SIZE            1024
#define JYMON_DEFAULT_REQUEST_COUNT       5
#define JYMON_DEFAULT_THREAD_COUNT        2
#define JYMON_MAX_THREAD_COUNT            64

const PWSTR JyMonPortName = L"JyMonPort";

typedef struct _JYMON_THREAD_CONTEXT
{
	HANDLE Port;
	HANDLE Completion;
} JYMON_THREAD_CONTEXT, *PJYMON_THREAD_CONTEXT;

#define NOTIFICATION_SIZE_TO_READ_FILE  1024
#define NOTIFICATION_SIZE_FILE_NAME     260

#pragma pack(8)
typedef struct _JYMON_NOTIFICATION
{
	HANDLE CurrentProcessId;
	UCHAR MajorFunction;
	WCHAR FileName[NOTIFICATION_SIZE_FILE_NAME];
	UCHAR Extended;
} JYMON_NOTIFICATION, *PJYMON_NOTIFICATION;
#pragma pop

typedef struct _JYMON_REPLY
{
	ULONG Reserved;
} JYMON_REPLY, *PJYMON_REPLY;

typedef struct _JYMON_NOTIFICATION_MESSAGE
{
	//
	// Required structure header.
	//
	FILTER_MESSAGE_HEADER MessageHeader;
	//
	// Private JYMON-specific fields begin here.
	//
	JYMON_NOTIFICATION Notification;
	//
	// Overlapped structure: this is not really part of the message
	// However we embed it instead of using a separately allocated overlap structure
	//
	OVERLAPPED Overlapped;
} JYMON_NOTIFICATION_MESSAGE, *PJYMON_NOTIFICATION_MESSAGE;
typedef struct _JYMON_REPLY_MESSAGE
{
	//
	//  Required structure header.
	//
	FILTER_REPLY_HEADER ReplyHeader;
	//
	//  Private JYMON-specific fields begin here.
	//
	JYMON_REPLY Reply;

} JYMON_REPLY_MESSAGE, *PJYMON_REPLY_MESSAGE;


VOID
Usage(
	VOID
	)
{
	printf("Connects to the JyMon filter\n");
	printf("Usage: jymonuser [requests per thread] [number of threads(1-64)]\n");
}

/*
* @brief    This is a worker thread
* @param    This thread context has a pointer to the port handle we use to send/receive messages,
*           and a completion port handle that was already associated with the comm. port by the caller.
* @return   HRESULT indicating the status of thread exit.
*/
HRESULT
JyMonWorker(
	_In_ PJYMON_THREAD_CONTEXT Context
	)
{
	PJYMON_NOTIFICATION Notification = NULL;
	JYMON_REPLY_MESSAGE ReplyMessage; // Reply with header
	PJYMON_NOTIFICATION_MESSAGE Message = NULL;
	LPOVERLAPPED Overlapped = NULL;
	BOOL Result;
	DWORD NumberOfBytesTransferred;
	HRESULT HandleResult;
	ULONG_PTR CompletionKey;

#pragma warning(push)
#pragma warning(disable:4127) // conditional expression is constant
	//
	// Obtain the message: note that the message we sent down via FltGetMessage() 
	// may NOT be the one dequeued off the completion queue: this is solely because 
	// there are multiple threads per single port handle. Any of the FilterGetMessage() 
	// issued messages can be completed in random order - and we will just 
	// dequeue a random one.
	//
	while (TRUE)
	{
#pragma warning(pop)
		//
		// Poll for messages from the filter component to scan.
		//
		if (FALSE == GetQueuedCompletionStatus(Context->Completion,
			&NumberOfBytesTransferred,
			&CompletionKey,
			&Overlapped,
			INFINITE))
		{
			if (NULL != Overlapped)
			{
				HandleResult = HRESULT_FROM_WIN32(GetLastError());
				if (0x00000040 != GetLastError())
				{
					printf("JyMon : GetQueuedCompletionStatus failed, HRESULT 0x%X\n", HandleResult);
					break;
				}
			}
		}

		//
		// To look up members in OVERLAPPPED structure, refer to 
		// https://msdn.microsoft.com/en-us/library/windows/desktop/ms684342(v=vs.85).aspx
		//
		Message = CONTAINING_RECORD(Overlapped,
			JYMON_NOTIFICATION_MESSAGE,
			Overlapped);
		printf("Received message, size %Id\n", Overlapped->InternalHigh);

		Notification = &Message->Notification;
		printf("CurrentProcessId : %i\n", (ULONG)Notification->CurrentProcessId);
		printf("MajorFunction : %i\n", Notification->MajorFunction);
		printf("Extended : %i\n", Notification->Extended);
		printf("Contents : %ws\n", Notification->FileName);


		//
		// Reserved codes for reply messages to filter.
		//
		/*
		ReplyMessage.ReplyHeader.Status = 0;
		ReplyMessage.ReplyHeader.MessageId = Message->MessageHeader.MessageId;
		ReplyMessage.Reply.Reserved = 0
		
		HandleResult = FilterReplyMessage(Context->Port,
			(PFILTER_REPLY_HEADER)&ReplyMessage,
			sizeof(ReplyMessage));
		if (SUCCEEDED(HandleResult))
		{
			printf("Replied message\n");
		}
		else
		{
			printf("JYMON: Error replying message. Error = 0x%X\n", HandleResult);
			break;
		}
		*/
		
		RtlZeroMemory(&Message->Overlapped, 0, sizeof(OVERLAPPED));
		HandleResult = FilterGetMessage(Context->Port,
			&Message->MessageHeader,
			FIELD_OFFSET(JYMON_NOTIFICATION_MESSAGE, Overlapped),
			&Message->Overlapped);
		if (HRESULT_FROM_WIN32(ERROR_IO_PENDING) != HandleResult) 
		{
			HandleResult = HRESULT_FROM_WIN32(GetLastError());
			break;
		}
	}

	if (!SUCCEEDED(HandleResult))
	{	
		if (HandleResult == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) 
		{
			//
			//  Scanner port disconncted.
			//
			printf("Scanner: Port is disconnected, probably due to scanner filter unloading.\n");
		}
		else 
		{
			printf("Scanner: Unknown error occured, HRESULT = 0x%X\n", HandleResult);
		}
	}

	if (NULL != Message)
	{
		free(Message);
	}

	return HandleResult;
}

int _cdecl
main(_In_ int argc,
	char* argv[])
{
	DWORD RequestCount = JYMON_DEFAULT_REQUEST_COUNT;
	DWORD ThreadCount = JYMON_DEFAULT_THREAD_COUNT;
	HANDLE Threads[JYMON_MAX_THREAD_COUNT];
	JYMON_THREAD_CONTEXT Context;
	PJYMON_NOTIFICATION_MESSAGE Message = NULL;
	HANDLE Port;
	HANDLE Completion;
	LPCWSTR JyMonPortName = L"\\JyMonPort";
	DWORD ThreadId;
	HRESULT HandleResult;
	DWORD i, j;

	if (argc > 1)
	{
		RequestCount = atoi(argv[1]);
		if (RequestCount <= 0)
		{
			Usage();
			return 1;
		}

		if (argc > 2)
		{
			ThreadCount = atoi(argv[2]);
		}

		if (ThreadCount <= 0 || ThreadCount > 64)
		{
			Usage();
			return 1;
		}
	}

	//
	//  Open a commuication channel to the filter
	//
	printf("JyMon: Connecting to the filter ...\n");
	HandleResult = FilterConnectCommunicationPort(JyMonPortName,
		0,
		NULL,
		0,
		NULL,
		&Port);
	if (IS_ERROR(HandleResult))
	{
		printf("ERROR : Connecting to filter port, HRESULT 0x%08x\n", HandleResult);
		return 2;
	}

	//
	//  Create a completion port to associate with this handle.
	//
	Completion = CreateIoCompletionPort(Port,
		NULL,
		0,
		ThreadCount);
	if (NULL == Completion)
	{
		printf("ERROR: Creating completion port, WinError %i\n", GetLastError());
		CloseHandle(Port);
		return 3;
	}

	printf("JyMon: Port = 0x%p Completion = 0x%p\n", Port, Completion);
	Context.Port = Port;
	Context.Completion = Completion;

	//
	//  Create specified number of threads.
	//
	__try
	{
		for (i = 0; i < ThreadCount; i++)
		{
			Threads[i] = CreateThread(NULL,
				0,
				(LPTHREAD_START_ROUTINE)JyMonWorker,
				&Context,
				0,
				&ThreadId);

			if (NULL == Threads[i])
			{
				//
				//  Couldn't create thread.
				//
				HandleResult = GetLastError();
				printf("ERROR: Couldn't create thread: %d\n", HandleResult);
				__leave;
			}

			for (j = 0; j < RequestCount; j++)
			{
				//
				//  Allocate the message.
				//
#pragma prefast(suppress:__WARNING_MEMORY_LEAK, "msg will not be leaked because it is freed in JyMonWorker")
				Message = (PJYMON_NOTIFICATION_MESSAGE)malloc(sizeof(JYMON_NOTIFICATION_MESSAGE));
				if (NULL == Message)
				{
					HandleResult = ERROR_NOT_ENOUGH_MEMORY;
					__leave;
				}
				RtlZeroMemory(&Message->Overlapped, sizeof(OVERLAPPED));

				//
				//  Request messages from the filter driver.
				//
				HandleResult = FilterGetMessage(Port,
					&Message->MessageHeader,
					FIELD_OFFSET(JYMON_NOTIFICATION_MESSAGE, Overlapped),
					&Message->Overlapped);
				if (HandleResult != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
				{
					__leave;
				}
			}
		}

		HandleResult = S_OK;
		WaitForMultipleObjectsEx(i, Threads, TRUE, INFINITE, FALSE);
	}
	__finally
	{
		if (NULL != Message)
		{
			free(Message);
		}
		printf("JYMON:  All done. Result = 0x%08x\n", HandleResult);

		CloseHandle(Port);
		CloseHandle(Completion);
	}

	getchar();
	return HandleResult;
}
