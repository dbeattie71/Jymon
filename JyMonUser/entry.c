#include <Windows.h>
#include <cstdlib>
#include <cstdio>
#include <fltUser.h>
#include <dontuse.h>
#include <share.h>
#include <assert.h>

#define JYMON_READ_BUFFER_SIZE            1024
#define JYMON_DEFAULT_REQUEST_COUNT       5
#define JYMON_DEFAULT_THREAD_COUNT        2
#define JYMON_MAX_THREAD_COUNT            64

typedef struct _JYMON_NOTIFICATION
{
	UCHAR MajorFunction;
} JYMON_NOTIFICATION, *PJYMON_NOTIFICATION;

typedef struct _JYMON_REPLY
{
	ULONG Reserved;
} JYMON_REPLY, *PJYMON_REPLY;

typedef struct _JYMON_THREAD_CONTEXT 
{
	HANDLE Port;
	HANDLE Completion;
} JYMON_THREAD_CONTEXT, *PJYMON_THREAD_CONTEXT;

#pragma pack(1)

typedef struct _JYMON_MESSAGE 
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
} JYMON_MESSAGE, *PJYMON_MESSAGE;

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

DWORD
JyMonWorker(
	_In_ PJYMON_THREAD_CONTEXT Context
	)
	/*++

	Routine Description

	This is a worker thread that


	Arguments

	Context  - This thread context has a pointer to the port handle we use to send/receive messages,
	and a completion port handle that was already associated with the comm. port by the caller

	Return Value

	HRESULT indicating the status of thread exit.

	--*/
{
	PJYMON_NOTIFICATION Notification;
	JYMON_REPLY_MESSAGE ReplyMessage;
	PJYMON_MESSAGE Message;
	LPOVERLAPPED Overlapped;
	BOOL Result;
	DWORD NumberOfBytesTransferred;
	HRESULT HandleResult;
	ULONG_PTR CompletionKey;

#pragma warning(push)
#pragma warning(disable:4127) // conditional expression is constant

	while (TRUE) 
	{
#pragma warning(pop)

		//
		// Poll for messages from the filter component to scan.
		//

		Result = GetQueuedCompletionStatus(Context->Completion, 
			                               &NumberOfBytesTransferred, 
			                               &CompletionKey,
			                               &Overlapped, 
			                               INFINITE);

		//
		// Obtain the message: note that the message we sent down via FltGetMessage() 
		// may NOT be the one dequeued off the completion queue: this is solely because 
		// there are multiple threads per single port handle. Any of the FilterGetMessage() 
		// issued messages can be completed in random order - and we will just 
		// dequeue a random one.
		//
		Message = CONTAINING_RECORD(Overlapped, 
			                        JYMON_MESSAGE, 
			                        Overlapped);
		if (!Result) 
		{
			HandleResult = HRESULT_FROM_WIN32(GetLastError());
			break;
		}

		printf("Received message, size %Id\n", Overlapped->InternalHigh);

		Notification = &Message->Notification;
		printf("MajorFunction : %i\n", Notification->MajorFunction);

		ReplyMessage.ReplyHeader.Status = 0;
		ReplyMessage.ReplyHeader.MessageId = Message->MessageHeader.MessageId;

		//
		//  Need to invert the boolean -- result is true if found
		//  foul language, in which case SafeToOpen should be set to false.
		//

		ReplyMessage.Reply.Reserved = 0;
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

		RtlZeroMemory(&Message->Overlapped, sizeof(OVERLAPPED));
		HandleResult = FilterGetMessage(Context->Port,
			&Message->MessageHeader,
			FIELD_OFFSET(JYMON_MESSAGE, Overlapped),
			&Message->Overlapped);

		if (HRESULT_FROM_WIN32(ERROR_IO_PENDING) != HandleResult)
		{
			break;
		}
	}

	if (!SUCCEEDED(HandleResult)) 
	{
		if (HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE) == HandleResult)
		{
			//
			//  JYMON port disconncted.
			//
			printf("JYMON: Port is disconnected, probably due to JYMON filter unloading.\n");
		}
		else 
		{
			printf("JYMON: Unknown error occured. Error = 0x%X\n", HandleResult);
		}
	}

	if (NULL != Message)
	{
		free(Message);
	}

	return HandleResult;
}

INT WINAPI
main(
	_In_ int argc,
	char* argv[]
	)
{
	DWORD RequestCount = JYMON_DEFAULT_REQUEST_COUNT;
	DWORD ThreadCount = JYMON_DEFAULT_THREAD_COUNT;
	HANDLE Threads[JYMON_MAX_THREAD_COUNT];
	JYMON_THREAD_CONTEXT Context;
	PJYMON_MESSAGE Message;
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

	//
	//  Create specified number of threads.
	//

	for (i = 0; i < ThreadCount; i++) 
	{
		Threads[i] = CreateThread(NULL,
			                      0,
			                      (LPTHREAD_START_ROUTINE)JyMonWorker,
			                      &Context,
			                      0,
			                      &ThreadId);

		if (Threads[i] == NULL) 
		{
			//
			//  Couldn't create thread.
			//

			HandleResult = GetLastError();
			printf("ERROR: Couldn't create thread: %d\n", hr);
			goto main_cleanup;
		}

		for (j = 0; j < requestCount; j++) {

			//
			//  Allocate the message.
			//

#pragma prefast(suppress:__WARNING_MEMORY_LEAK, "msg will not be leaked because it is freed in JyMonWorker")
			msg = malloc(sizeof(JYMON_MESSAGE));

			if (msg == NULL) {

				hr = ERROR_NOT_ENOUGH_MEMORY;
				goto main_cleanup;
			}

			memset(&msg->Ovlp, 0, sizeof(OVERLAPPED));

			//
			//  Request messages from the filter driver.
			//

			HandleResult = FilterGetMessage(port,
				&msg->MessageHeader,
				FIELD_OFFSET(JYMON_MESSAGE, Ovlp),
				&msg->Ovlp);

			if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {

				free(msg);
				goto main_cleanup;
			}
		}
	}

	hr = S_OK;

	WaitForMultipleObjectsEx(i, threads, TRUE, INFINITE, FALSE);

main_cleanup:

	printf("JYMON:  All done. Result = 0x%08x\n", hr);

	CloseHandle(port);
	CloseHandle(completion);

	return HandleResult;
}
