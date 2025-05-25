using System;
using System.Text;

namespace RC6Encryption
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("RC6 Encryption and Decryption Example");
            Console.WriteLine("====================================");

            // Example key "ABC" as described in your example
            string key = "ABC";
            RC6Cipher rc6 = new RC6Cipher(key);

            // Example plaintext "Anh" with padding to 4 bytes
            string plaintext = "Anh";
            byte[] plaintextBytes = Encoding.ASCII.GetBytes(plaintext);

            // Pad to multiple of 16 bytes for demonstration
            byte[] paddedPlaintext = new byte[16];
            Array.Copy(plaintextBytes, paddedPlaintext, plaintextBytes.Length);

            Console.WriteLine($"Original Text: {plaintext}");
            Console.WriteLine($"Key: {key}");

            // Display the original bytes in ASCII and hex
            Console.WriteLine("\nOriginal Bytes:");
            DisplayBytes(paddedPlaintext);

            // Encrypt
            byte[] ciphertext = rc6.Encrypt(paddedPlaintext);
            Console.WriteLine("\nEncrypted Bytes:");
            DisplayBytes(ciphertext);

            // Decrypt
            byte[] decryptedBytes = rc6.Decrypt(ciphertext);
            Console.WriteLine("\nDecrypted Bytes:");
            DisplayBytes(decryptedBytes);

            // Convert decrypted bytes back to string
            string decryptedText = Encoding.ASCII.GetString(decryptedBytes).TrimEnd('\0');
            Console.WriteLine($"\nDecrypted Text: {decryptedText}");

            // Verify if decryption is correct
            Console.WriteLine("\nVerification:");
            bool match = true;
            for (int i = 0; i < plaintextBytes.Length; i++)
            {
                if (plaintextBytes[i] != decryptedBytes[i])
                {
                    match = false;
                    break;
                }
            }
            Console.WriteLine(match ? "Decryption successful!" : "Decryption failed!");
        }

        static void DisplayBytes(byte[] bytes)
        {
            Console.Write("ASCII: ");
            foreach (byte b in bytes)
            {
                char c = (char)b;
                if (b == 0)
                    Console.Write("\\0 ");
                else if (char.IsControl(c))
                    Console.Write($"\\{(int)b} ");
                else
                    Console.Write($"{c} ");
            }

            Console.Write("\nHEX: ");
            foreach (byte b in bytes)
            {
                Console.Write($"{b:X2} ");
            }

            Console.Write("\nDEC: ");
            foreach (byte b in bytes)
            {
                Console.Write($"{b} ");
            }
            Console.WriteLine();

            // Display as 32-bit words for RC6
            Console.WriteLine("32-bit Words (Little Endian):");
            for (int i = 0; i < bytes.Length; i += 4)
            {
                uint word = 0;
                for (int j = 0; j < 4; j++)
                {
                    if (i + j < bytes.Length)
                    {
                        word |= (uint)(bytes[i + j] << (8 * j));
                    }
                }
                Console.WriteLine($"Word {i / 4}: {word} (0x{word:X8})");
            }
        }
    }
}
