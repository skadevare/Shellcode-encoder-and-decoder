using System;
using System.Text;
using System.IO;

namespace bufEncoder
{
    class Program
    {
        static void Main(string[] args)
        {
            // The buf to be encoded
            byte[] buf = new byte[510] {
0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,.... };



            // Encode the payload with XOR (fixed key)
            byte[] encoded = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)((uint)buf[i] ^ 0x42);
            }

            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            int totalCount = encoded.Length;
            for (int count = 0; count < totalCount; count++)
            {
                byte b = encoded[count];

                if ((count + 1) == totalCount) // Dont append comma for last item
                {
                    hex.AppendFormat("0x{0:x2}", b);
                }
                else
                {
                    hex.AppendFormat("0x{0:x2}, ", b);
                }

                if ((count + 1) % 15 == 0)
                {
                    hex.Append("\n");
                }
            }

            Console.WriteLine($"XOR payload (key: 0xDE):");
            Console.WriteLine($"byte[] buf = new byte[{buf.Length}] {{\n{hex}\n}};");
        }
        
    }
}
