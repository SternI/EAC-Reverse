## Post: [Latest EAC Driver IDA Database with Named/Decrypted Imports](https://www.unknowncheats.me/forum/anti-cheat-bypass/679385-eac-driver-ida-database-named-decrypted-imports.html)

# Latest Fortnite's EAC Driver IDA Database with Named/Decrypted Imports

## Database Download:
- **IDA 8:** [Download from UnknownCheats](https://www.unknowncheats.me/forum/downloads.php?do=file&id=48313)
- **IDA 9:** [Download from UnknownCheats](https://www.unknowncheats.me/forum/downloads.php?do=file&id=48082)

## Imports:
```yaml
// ntoskrnl.exe
Offset: 0x171210, Module: ntoskrnl.exe, Import: MmUserProbeAddress
Offset: 0x171E98, Module: ntoskrnl.exe, Import: MmHighestUserAddress
Offset: 0x171EE8, Module: ntoskrnl.exe, Import: MmSystemRangeStart
Offset: 0x171798, Module: ntoskrnl.exe, Import: PsGetProcessInheritedFromUniqueProcessId
Offset: 0x171F18, Module: ntoskrnl.exe, Import: IoThreadToProcess
Offset: 0x172388, Module: ntoskrnl.exe, Import: IoThreadToProcess
Offset: 0x1721E8, Module: ntoskrnl.exe, Import: ExAcquireFastMutexUnsafe
Offset: 0x1721C8, Module: ntoskrnl.exe, Import: ExReleaseFastMutexUnsafe
Offset: 0x1722C8, Module: ntoskrnl.exe, Import: ExGetPreviousMode
Offset: 0x171CC8, Module: ntoskrnl.exe, Import: KeResetEvent
Offset: 0x1712A8, Module: ntoskrnl.exe, Import: IoBuildDeviceIoControlRequest
Offset: 0x171AF8, Module: ntoskrnl.exe, Import: KeInitializeEvent
Offset: 0x172378, Module: ntoskrnl.exe, Import: PsGetCurrentThreadProcessId
Offset: 0x1713C8, Module: ntoskrnl.exe, Import: ObDereferenceObjectDeferDelete
Offset: 0x171CF8, Module: ntoskrnl.exe, Import: KeSetEvent
Offset: 0x171CA8, Module: ntoskrnl.exe, Import: KeWaitForSingleObject
Offset: 0x172278, Module: ntoskrnl.exe, Import: KxAcquireSpinLock
Offset: 0x172268, Module: ntoskrnl.exe, Import: KxReleaseSpinLock
Offset: 0x171B58, Module: ntoskrnl.exe, Import: KeReleaseGuardedMutex
Offset: 0x171B68, Module: ntoskrnl.exe, Import: ExAcquireFastMutex
Offset: 0x171458, Module: ntoskrnl.exe, Import: ExAcquirePushLockExclusiveEx
Offset: 0x1717B8, Module: ntoskrnl.exe, Import: ExReleasePushLockEx
Offset: 0x1721A8, Module: ntoskrnl.exe, Import: HalPutDmaAdapter (ObDereferenceObject, ObfDereferenceObject, PsDereferenceSiloContext)
Offset: 0x172448, Module: ntoskrnl.exe, Import: ObfReferenceObject
Offset: 0x1721D8, Module: ntoskrnl.exe, Import: KeLeaveCriticalRegion
Offset: 0x1714B8, Module: ntoskrnl.exe, Import: IoGetStackLimits
Offset: 0x1721B8, Module: ntoskrnl.exe, Import: KeEnterCriticalRegion
Offset: 0x171C78, Module: ntoskrnl.exe, Import: KeAreAllApcsDisabled
Offset: 0x171718, Module: ntoskrnl.exe, Import: PsGetProcessSectionBaseAddress
Offset: 0x171BE8, Module: ntoskrnl.exe, Import: KeStackAttachProcess
Offset: 0x171D08, Module: ntoskrnl.exe, Import: KeReleaseMutex
Offset: 0x1724E8, Module: ntoskrnl.exe, Import: MmCopyMemory
Offset: 0x1724A8, Module: ntoskrnl.exe, Import: MmMapIoSpaceEx
Offset: 0x172238, Module: ntoskrnl.exe, Import: MmAllocateContiguousNodeMemory
Offset: 0x172508, Module: ntoskrnl.exe, Import: MmUnmapIoSpace
Offset: 0x172218, Module: ntoskrnl.exe, Import: MmFreeContiguousMemory
Offset: 0x171D88, Module: ntoskrnl.exe, Import: PsGetProcessId
Offset: 0x172488, Module: ntoskrnl.exe, Import: MmProbeAndLockPages
Offset: 0x1720B8, Module: ntoskrnl.exe, Import: KeInsertQueueDpc
Offset: 0x172068, Module: ntoskrnl.exe, Import: IoGetTopLevelIrp
Offset: 0x171D98, Module: ntoskrnl.exe, Import: PsGetCurrentProcess
Offset: 0x171B08, Module: ntoskrnl.exe, Import: ExAcquireSpinLockExclusive
Offset: 0x171D28, Module: ntoskrnl.exe, Import: KeDelayExecutionThread
Offset: 0x172368, Module: ntoskrnl.exe, Import: KeSetPriorityThread
Offset: 0x171C98, Module: ntoskrnl.exe, Import: KeWaitForMultipleObjects
Offset: 0x171EB8, Module: ntoskrnl.exe, Import: KeQueryTimeIncrement
Offset: 0x172338, Module: ntoskrnl.exe, Import: PsIsThreadTerminating
Offset: 0x1715F8, Module: ntoskrnl.exe, Import: RtlVirtualUnwind
Offset: 0x172128, Module: ntoskrnl.exe, Import: RtlLookupFunctionEntry
Offset: 0x1722D8, Module: ntoskrnl.exe, Import: KeAlertThread
Offset: 0x1724F8, Module: ntoskrnl.exe, Import: MmGetPhysicalAddress
Offset: 0x171B18, Module: ntoskrnl.exe, Import: PsGetThreadWin32Thread
Offset: 0x171688, Module: ntoskrnl.exe, Import: ExReleaseSpinLockExclusive
Offset: 0x171958, Module: ntoskrnl.exe, Import: PsGetProcessWow64Process
Offset: 0x171FD8, Module: ntoskrnl.exe, Import: PsGetCurrentThreadId
Offset: 0x1720E8, Module: ntoskrnl.exe, Import: KeFlushQueuedDpcs
Offset: 0x1722E8, Module: ntoskrnl.exe, Import: PsIsSystemThread
Offset: 0x1713F8, Module: ntoskrnl.exe, Import: RtlInitializeBitMap
Offset: 0x171D38, Module: ntoskrnl.exe, Import: PsGetThreadId
Offset: 0x171E88, Module: ntoskrnl.exe, Import: PsGetProcessCreateTimeQuadPart
Offset: 0x171378, Module: ntoskrnl.exe, Import: PsGetProcessPeb
Offset: 0x1722F8, Module: ntoskrnl.exe, Import: PsGetThreadProcessId
Offset: 0x172058, Module: ntoskrnl.exe, Import: PsGetProcessImageFileName
Offset: 0x171ED8, Module: ntoskrnl.exe, Import: PsGetProcessExitProcessCalled
Offset: 0x172118, Module: ntoskrnl.exe, Import: KeSignalCallDpcDone
Offset: 0x171698, Module: ntoskrnl.exe, Import: ObIsKernelHandle
Offset: 0x172048, Module: ntoskrnl.exe, Import: KeInitializeDpc
Offset: 0x171CB8, Module: ntoskrnl.exe, Import: KeInitializeMutex
Offset: 0x171488, Module: ntoskrnl.exe, Import: IoEnumerateDeviceObjectList
Offset: 0x172018, Module: ntoskrnl.exe, Import: __C_specific_handler
Offset: 0x1723B8, Module: ntoskrnl.exe, Import: _vsnwprintf
Offset: 0x1723D8, Module: ntoskrnl.exe, Import: _vsnprintf
Offset: 0x171738, Module: ntoskrnl.exe, Import: ExfUnblockPushLock
Offset: 0x1719A8, Module: ntoskrnl.exe, Import: ZwWaitForSingleObject
Offset: 0x1723C8, Module: ntoskrnl.exe, Import: ZwReadFile
Offset: 0x1723F8, Module: ntoskrnl.exe, Import: ZwWriteFile
Offset: 0x172208, Module: ntoskrnl.exe, Import: ZwClose
Offset: 0x172398, Module: ntoskrnl.exe, Import: ZwQueryInformationFile
Offset: 0x171E38, Module: ntoskrnl.exe, Import: ZwQueryValueKey
Offset: 0x171CE8, Module: ntoskrnl.exe, Import: ZwAllocateVirtualMemory
Offset: 0x172078, Module: ntoskrnl.exe, Import: ZwQueryInformationProcess
Offset: 0x171568, Module: ntoskrnl.exe, Import: ZwSetInformationProcess
Offset: 0x171DB8, Module: ntoskrnl.exe, Import: ZwFreeVirtualMemory
Offset: 0x172638, Module: ntoskrnl.exe, Import: ZwQueryVirtualMemory
Offset: 0x172348, Module: ntoskrnl.exe, Import: ZwQueryInformationThread
Offset: 0x172658, Module: ntoskrnl.exe, Import: ZwMapViewOfSection
Offset: 0x171988, Module: ntoskrnl.exe, Import: ZwTerminateProcess
Offset: 0x1716D8, Module: ntoskrnl.exe, Import: ZwOpenFile
Offset: 0x172248, Module: ntoskrnl.exe, Import: ZwQuerySystemInformation
Offset: 0x1715D8, Module: ntoskrnl.exe, Import: ZwOpenSection
Offset: 0x171998, Module: ntoskrnl.exe, Import: ZwCreateSection
Offset: 0x171DA8, Module: ntoskrnl.exe, Import: ZwProtectVirtualMemory
Offset: 0x1720A8, Module: ntoskrnl.exe, Import: ZwQuerySection
Offset: 0x172228, Module: ntoskrnl.exe, Import: ZwCreateFile
Offset: 0x171348, Module: ntoskrnl.exe, Import: ZwOpenDirectoryObject
Offset: 0x171668, Module: ntoskrnl.exe, Import: ZwSetInformationObject
Offset: 0x1723E8, Module: ntoskrnl.exe, Import: ZwDeleteFile
Offset: 0x171DD8, Module: ntoskrnl.exe, Import: ZwFlushVirtualMemory
Offset: 0x1720F8, Module: ntoskrnl.exe, Import: ZwOpenSymbolicLinkObject
Offset: 0x1723A8, Module: ntoskrnl.exe, Import: ZwQueryFullAttributesFile
Offset: 0x172108, Module: ntoskrnl.exe, Import: ZwQuerySymbolicLinkObject
Offset: 0x171DC8, Module: ntoskrnl.exe, Import: ZwSetInformationVirtualMemory
Offset: 0x171A78, Module: ntoskrnl.exe, Import: ZwTraceControl
Offset: 0x171DF8, Module: ntoskrnl.exe, Import: KeBugCheckEx
Offset: 0x172148, Module: ntoskrnl.exe, Import: KeSignalCallDpcSynchronize
Offset: 0x171FA8, Module: ntoskrnl.exe, Import: MmGetVirtualForPhysical
Offset: 0x171C48, Module: ntoskrnl.exe, Import: MmIsAddressValid
Offset: 0x172318, Module: ntoskrnl.exe, Import: PsGetCurrentThreadStackBase
Offset: 0x172358, Module: ntoskrnl.exe, Import: PsGetCurrentThreadStackLimit
Offset: 0x171EF8, Module: ntoskrnl.exe, Import: IoGetDeviceObjectPointer
Offset: 0x172528, Module: ntoskrnl.exe, Import: RtlMultiByteToUnicodeN
Offset: 0x171C38, Module: ntoskrnl.exe, Import: ObReferenceObjectByName
Offset: 0x171CD8, Module: ntoskrnl.exe, Import: NtCreateEvent
Offset: 0x171C28, Module: ntoskrnl.exe, Import: ObOpenObjectByName
Offset: 0x172158, Module: ntoskrnl.exe, Import: SeQueryInformationToken
Offset: 0x172328, Module: ntoskrnl.exe, Import: ObReferenceObjectByHandle
Offset: 0x1721F8, Module: ntoskrnl.exe, Import: RtlEqualUnicodeString
Offset: 0x1718C8, Module: ntoskrnl.exe, Import: ObCloseHandle
Offset: 0x1713A8, Module: ntoskrnl.exe, Import: ObQueryNameString
Offset: 0x172088, Module: ntoskrnl.exe, Import: IoQueryFileDosDeviceName
Offset: 0x171D48, Module: ntoskrnl.exe, Import: PsLookupThreadByThreadId
Offset: 0x171FE8, Module: ntoskrnl.exe, Import: PsLookupProcessByProcessId
Offset: 0x1713E8, Module: ntoskrnl.exe, Import: PsAcquireProcessExitSynchronization
Offset: 0x172518, Module: ntoskrnl.exe, Import: RtlCompareString
Offset: 0x171C58, Module: ntoskrnl.exe, Import: RtlCompareUnicodeString
Offset: 0x171B88, Module: ntoskrnl.exe, Import: ObOpenObjectByPointer
Offset: 0x172178, Module: ntoskrnl.exe, Import: PsReferencePrimaryToken
Offset: 0x171878, Module: ntoskrnl.exe, Import: PsReferenceProcessFilePointer
Offset: 0x1714A8, Module: ntoskrnl.exe, Import: ObGetObjectType
Offset: 0x1720D8, Module: ntoskrnl.exe, Import: PsDereferencePrimaryToken
Offset: 0x171F98, Module: ntoskrnl.exe, Import: RtlUTF8ToUnicodeN
Offset: 0x172538, Module: ntoskrnl.exe, Import: RtlUnicodeToUTF8N
Offset: 0x171398, Module: ntoskrnl.exe, Import: IoGetDeviceInterfaces
Offset: 0x171E78, Module: ntoskrnl.exe, Import: PsGetProcessExitStatus
Offset: 0x171F78, Module: ntoskrnl.exe, Import: ExRaiseDatatypeMisalignment
Offset: 0x171BC8, Module: ntoskrnl.exe, Import: SeRegisterImageVerificationCallback
Offset: 0x172308, Module: ntoskrnl.exe, Import: IoGetInitialStack
Offset: 0x1718B8, Module: ntoskrnl.exe, Import: RtlCreateUserThread
Offset: 0x172198, Module: ntoskrnl.exe, Import: SeUnregisterImageVerificationCallback
Offset: 0x171F68, Module: ntoskrnl.exe, Import: ExRaiseAccessViolation
Offset: 0x171A38, Module: ntoskrnl.exe, Import: ExAllocatePoolWithTag
Offset: 0x171FC8, Module: ntoskrnl.exe, Import: ExFreePoolWithTag
Offset: 0x171228, Module: ntoskrnl.exe, Import: KdEnteredDebugger
Offset: 0x1711B0, Module: ntoskrnl.exe, Import: NtGlobalFlag
Offset: 0x171B78, Module: ntoskrnl.exe, Import: PsProcessType
Offset: 0x171D18, Module: ntoskrnl.exe, Import: PsInitialSystemProcess
Offset: 0x1722B8, Module: ntoskrnl.exe, Import: PsThreadType
Offset: 0x171C88, Module: ntoskrnl.exe, Import: ExEventObjectType
Offset: 0x1711C8, Module: ntoskrnl.exe, Import: IoDriverObjectType
 
// cng.sys
Offset: 0x1725F8, Module: cng.sys, Import: BCryptHashData
Offset: 0x1725C8, Module: cng.sys, Import: BCryptGenerateSymmetricKey
Offset: 0x172568, Module: cng.sys, Import: BCryptDestroyKey
Offset: 0x1725A8, Module: cng.sys, Import: BCryptDestroyHash
Offset: 0x172558, Module: cng.sys, Import: BCryptFinishHash
Offset: 0x172548, Module: cng.sys, Import: BCryptCreateHash
Offset: 0x1725D8, Module: cng.sys, Import: BCryptGetProperty
Offset: 0x1725E8, Module: cng.sys, Import: BCryptVerifySignature
Offset: 0x172608, Module: cng.sys, Import: BCryptDecrypt
Offset: 0x172578, Module: cng.sys, Import: BCryptSetProperty
Offset: 0x172598, Module: cng.sys, Import: BCryptOpenAlgorithmProvider
Offset: 0x172588, Module: cng.sys, Import: BCryptCloseAlgorithmProvider
Offset: 0x1725B8, Module: cng.sys, Import: BCryptImportKeyPair
 
// fltMgr.sys
Offset: 0x171308, Module: fltMgr.sys, Import: FltReadFile
Offset: 0x171F38, Module: fltMgr.sys, Import: FltGetFileNameInformation
Offset: 0x171F08, Module: fltMgr.sys, Import: FltIsDirectory
Offset: 0x171968, Module: fltMgr.sys, Import: FltGetRequestorProcess
Offset: 0x171858, Module: fltMgr.sys, Import: FltAllocatePoolAlignedWithTag
Offset: 0x171338, Module: fltMgr.sys, Import: FltFreePoolAlignedWithTag
Offset: 0x171F28, Module: fltMgr.sys, Import: FltParseFileNameInformation
Offset: 0x172188, Module: fltMgr.sys, Import: FltGetFileNameInformationUnsafe
Offset: 0x171748, Module: fltMgr.sys, Import: FltQueryInformationFile
Offset: 0x171F58, Module: fltMgr.sys, Import: FltReleaseFileNameInformation
Offset: 0x171588, Module: fltMgr.sys, Import: FltStartFiltering
Offset: 0x171938, Module: fltMgr.sys, Import: FltUnregisterFilter
 
// tbs.sys
Offset: 0x171AB8, Module: tbs.sys, Import: Tbsi_Context_Create
Offset: 0x171AD8, Module: tbs.sys, Import: Tbsi_GetDeviceInfo
Offset: 0x171358, Module: tbs.sys, Import: Tbsip_Cancel_Commands
Offset: 0x171AE8, Module: tbs.sys, Import: Tbsip_Context_Close
Offset: 0x171AC8, Module: tbs.sys, Import: Tbsip_Submit_Command
```

## <b>How I Got Them?</b>
Everything is automated without dumping anything, but everything was processed from the loaded driver to get and decrypt the keys of course.

Decryptions:
I made a function to get all "DecryptImport" function xrefs, then parse the parameters to extract the encrypted import/key.
I also made a function to handle the necessary encryptions.

### <b>Names</b>:
I get all loaded modules and check if the decrypted address falls within a module's range.
Then I get the module's exports and check if the address matches the decrypted address.