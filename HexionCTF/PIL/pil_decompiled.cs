using System;
using System.Collections;
using System.IO;
using System.Text;

namespace csharp {
    internal class Program {
    private static FileStream piFile;

    private static void Main(string[] args) {
        Program.piFile = new FileStream("one-million-digits.txt", FileMode.Open, FileAccess.Read);
        Program.Hide("original.bmp", "result.bmp", "<CENSORED>");
    }

    private static void Hide(string srcPath, string dstPath, string secret) {
        BitArray bitArray = new BitArray(Encoding.UTF8.GetBytes(secret));

        byte[] bytes = File.ReadAllBytes(srcPath);
        int num1 = (int) bytes[14] + 14;
        for (int index1 = 0; index1 < bitArray.Length; ++index1) {
            int index2 = num1 + Program.GetNextPiDigit();
            byte num2 = (byte) (254U & (uint) bytes[index2]);
            bytes[index2] = (byte) ((uint) num2 + (uint) Convert.ToByte(bitArray[index1]));
            num1 += 10;
        }

        File.WriteAllBytes(dstPath, bytes);
    }

    private static int GetNextPiDigit() {
        int num = Program.piFile.ReadByte();
        if (num == 10) {
            num = Program.piFile.ReadByte();
        }
        return num - 48;
        }
    }
}