using System;
using System.Text;

namespace RC6Encryption
{
    public class RC6Cipher
    {
        // Constants for RC6
        private const int W = 32;                  // Word size in bits
        private const int R = 20;                  // Number of rounds
        private const int LOG_W = 5;               // log_2(W)
        private const uint P = 0xB7E15163;         // Magic constant P (derived from e)
        private const uint Q = 0x9E3779B9;         // Magic constant Q (derived from golden ratio)

        private uint[] S;                          // Key schedule array

        public RC6Cipher(string key)
        {
            // Convert the key from string to bytes
            byte[] keyBytes = Encoding.ASCII.GetBytes(key);
            GenerateSubkeys(keyBytes);
        }

        private void GenerateSubkeys(byte[] key)
        {
            // The size of S is 2r+4 words
            int t = 2 * R + 4;
            S = new uint[t];

            // Initialize S with magic constants
            S[0] = P;
            for (int i = 1; i < t; i++)
            {
                S[i] = S[i - 1] + Q;
            }

            // Convert key to array of words (uint)
            int c = key.Length / 4;
            if (key.Length % 4 != 0) c++;
            uint[] L = new uint[c];

            for (int i = 0; i < key.Length; i++)
            {
                L[i / 4] = (L[i / 4] << 8) + key[i];
            }

            // Key mixing
            int v = 3 * Math.Max(c, t);
            uint A = 0, B = 0;
            int i1 = 0, j = 0;

            for (int s = 0; s < v; s++)
            {
                A = S[i1] = RotateLeft(S[i1] + A + B, 3);
                B = L[j] = RotateLeft(L[j] + A + B, (int)(A + B) % W);
                i1 = (i1 + 1) % t;
                j = (j + 1) % c;
            }
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            // Ensure input is properly padded to 16 bytes (4 words of 4 bytes each)
            int paddedLength = (plaintext.Length + 15) / 16 * 16;
            byte[] paddedText = new byte[paddedLength];
            Array.Copy(plaintext, paddedText, plaintext.Length);

            byte[] ciphertext = new byte[paddedLength];

            // Process each block (16 bytes = 4 words)
            for (int i = 0; i < paddedLength; i += 16)
            {
                // Convert 16 bytes to 4 words (A, B, C, D)
                uint A = BytesToUInt(paddedText, i);
                uint B = BytesToUInt(paddedText, i + 4);
                uint C = BytesToUInt(paddedText, i + 8);
                uint D = BytesToUInt(paddedText, i + 12);

                // Pre-whitening
                B += S[0];
                D += S[1];

                // Rounds
                for (int j = 1; j <= R; j++)
                {
                    // t = (B * (2B + 1)) <<< log_w
                    uint t = RotateLeft((B * (2 * B + 1)), LOG_W);
                    // u = (D * (2D + 1)) <<< log_w
                    uint u = RotateLeft((D * (2 * D + 1)), LOG_W);

                    // A = ((A XOR t) <<< u) + S[2*j]
                    A = RotateLeft(A ^ t, (int)(u % W)) + S[2 * j];
                    // C = ((C XOR u) <<< t) + S[2*j + 1]
                    C = RotateLeft(C ^ u, (int)(t % W)) + S[2 * j + 1];

                    // Rotate (A, B, C, D) to (B, C, D, A)
                    uint temp = A;
                    A = B;
                    B = C;
                    C = D;
                    D = temp;
                }

                // Post-whitening
                A += S[2 * R + 2];
                C += S[2 * R + 3];

                // Convert back to bytes and store in ciphertext
                UIntToBytes(A, ciphertext, i);
                UIntToBytes(B, ciphertext, i + 4);
                UIntToBytes(C, ciphertext, i + 8);
                UIntToBytes(D, ciphertext, i + 12);
            }

            return ciphertext;
        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            int length = ciphertext.Length;
            byte[] plaintext = new byte[length];

            // Process each block (16 bytes = 4 words)
            for (int i = 0; i < length; i += 16)
            {
                // Convert 16 bytes to 4 words (A, B, C, D)
                uint A = BytesToUInt(ciphertext, i);
                uint B = BytesToUInt(ciphertext, i + 4);
                uint C = BytesToUInt(ciphertext, i + 8);
                uint D = BytesToUInt(ciphertext, i + 12);

                // Reverse post-whitening
                C -= S[2 * R + 3];
                A -= S[2 * R + 2];

                // Rounds in reverse order
                for (int j = R; j >= 1; j--)
                {
                    // Rotate (B, C, D, A) to (A, B, C, D)
                    uint temp = D;
                    D = C;
                    C = B;
                    B = A;
                    A = temp;

                    // u = (D * (2D + 1)) <<< log_w
                    uint u = RotateLeft((D * (2 * D + 1)), LOG_W);
                    // t = (B * (2B + 1)) <<< log_w
                    uint t = RotateLeft((B * (2 * B + 1)), LOG_W);

                    // C = (RotateRight(C - S[2*j + 1], (int)(t % W))) XOR u
                    C = RotateRight(C - S[2 * j + 1], (int)(t % W)) ^ u;
                    // A = (RotateRight(A - S[2*j], (int)(u % W))) XOR t
                    A = RotateRight(A - S[2 * j], (int)(u % W)) ^ t;
                }

                // Reverse pre-whitening
                D -= S[1];
                B -= S[0];

                // Convert back to bytes and store in plaintext
                UIntToBytes(A, plaintext, i);
                UIntToBytes(B, plaintext, i + 4);
                UIntToBytes(C, plaintext, i + 8);
                UIntToBytes(D, plaintext, i + 12);
            }

            return plaintext;
        }

        // Helper methods
        private static uint RotateLeft(uint value, int shift)
        {
            shift %= W;
            return ((value << shift) | (value >> (W - shift)));
        }

        private static uint RotateRight(uint value, int shift)
        {
            shift %= W;
            return ((value >> shift) | (value << (W - shift)));
        }

        private static uint BytesToUInt(byte[] bytes, int startIndex)
        {
            uint value = 0;
            for (int i = 0; i < 4; i++)
            {
                if (startIndex + i < bytes.Length)
                {
                    value |= (uint)(bytes[startIndex + i] << (8 * i));
                }
            }
            return value;
        }

        private static void UIntToBytes(uint value, byte[] bytes, int startIndex)
        {
            for (int i = 0; i < 4; i++)
            {
                bytes[startIndex + i] = (byte)((value >> (8 * i)) & 0xFF);
            }
        }
    }
}
