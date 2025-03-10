using System;
using System.Collections.Generic;

public class Aes256Helper
{
    // Mảng S-box
    private static readonly byte[] SBox = new byte[]
    {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };

    // Mảng InvS-box
    private static readonly byte[] InvSBox = new byte[]
    {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };

    // Mảng Rcon
    private static readonly byte[] Rc = new byte[]
    {
        0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39
    };

    // Hiển thị giá trị hex của một từ 32-bit
    public static void ShowWord(uint w)
    {
        Console.Write(w.ToString("X8"));
    }

    // Xoay vòng trái 1 byte
    public static uint RotWord(uint w)
    {
        return (w << 8) | (w >> 24);
    }

    // Thay thế từng byte bằng S-box
    public static uint SubWord(uint w)
    {
        uint kq = 0;
        for (int i = 0; i < 4; i++)
        {
            byte b = (byte)((w >> (24 - i * 8)) & 0xFF);
            byte subB = SBox[b];
            kq = (kq << 8) | subB;
        }
        return kq;
    }

    // XOR với giá trị từ Rcon
    public static uint XorRcon(uint w, int j)
    {
        byte rcon = Rc[j];
        uint kq = w ^ ((uint)rcon << 24);
        return kq;
    }

    // Hàm G kết hợp RotWord, SubWord và XorRcon
    public static uint G(uint w, int j)
    {
        uint rotW = RotWord(w);
        uint subW = SubWord(rotW);
        uint kq = XorRcon(subW, j);
        return kq;
    }

    // Mở rộng khóa
    public static uint[] KeyExpansion(uint[] Key)
    {
        uint[] w = new uint[60]; // Tăng từ 44 lên 60 words

        // Copy khóa ban đầu
        for (int i = 0; i < 8; i++) // Copy 8 words thay vì 4
        {
            w[i] = Key[i];
        }

        for (int i = 8; i < 60; i++)
        {
            if (i % 8 == 0)
            {
                w[i] = w[i - 8] ^ G(w[i - 1], i / 8);
            }
            else if (i % 8 == 4) // Thêm điều kiện đặc biệt cho AES-256
            {
                w[i] = w[i - 8] ^ SubWord(w[i - 1]);
            }
            else
            {
                w[i] = w[i - 8] ^ w[i - 1];
            }
        }
        return w;
    }

    // Thêm khóa vòng
    public static uint[] AddRoundKey(uint[] state, uint[] K, int round)
    {
        uint[] kq = new uint[4];
        for (int i = 0; i < 4; i++)
        {
            kq[i] = state[i] ^ K[round * 4 + i];
        }
        return kq;
    }

    // Thay thế byte bằng S-box cho state
    public static uint[] SubBytes(uint[] state)
    {
        uint[] kq = new uint[4];
        for (int i = 0; i < 4; i++)
        {
            kq[i] = SubWord(state[i]);
        }
        return kq;
    }

    // Dịch chuyển hàng
    public static uint[] ShiftRows(uint[] state)
    {
        uint[] kq = new uint[4];
        for (int i = 0; i < 4; i++)
        {
            uint byte1 = (state[i] & 0xFF000000) >> 24;
            uint byte2 = (state[(i + 1) % 4] & 0x00FF0000) >> 16;
            uint byte3 = (state[(i + 2) % 4] & 0x0000FF00) >> 8;
            uint byte4 = state[(i + 3) % 4] & 0x000000FF;
            kq[i] = (byte1 << 24) | (byte2 << 16) | (byte3 << 8) | byte4;
        }
        return kq;
    }

    // Nhân trong trường Galois
    public static byte Nhan2(byte w)
    {
        uint kq = (uint)w << 1;
        if ((w & 0x80) != 0)
        {
            kq ^= 0x1B;
        }
        return (byte)(kq & 0xFF);
    }

    public static byte Nhan3(byte w)
    {
        return (byte)(Nhan2(w) ^ w);
    }

    public static byte Nhan9(byte w)
    {
        return (byte)(Nhan2(Nhan2(Nhan2(w))) ^ w);
    }

    public static byte NhanB(byte w)
    {
        return (byte)(Nhan2(Nhan2(Nhan2(w))) ^ Nhan2(w) ^ w);
    }

    public static byte NhanD(byte w)
    {
        return (byte)(Nhan2(Nhan2(Nhan2(w))) ^ Nhan2(Nhan2(w)) ^ w);
    }

    public static byte NhanE(byte w)
    {
        return (byte)(Nhan2(Nhan2(Nhan2(w))) ^ Nhan2(Nhan2(w)) ^ Nhan2(w));
    }

    // Trộn cột
    public static uint[] MixColumns(uint[] state)
    {
        uint[] kq = new uint[4];
        for (int i = 0; i < 4; i++)
        {
            byte b0 = (byte)((state[i] >> 24) & 0xFF);
            byte b1 = (byte)((state[i] >> 16) & 0xFF);
            byte b2 = (byte)((state[i] >> 8) & 0xFF);
            byte b3 = (byte)(state[i] & 0xFF);

            byte r0 = (byte)(Nhan2(b0) ^ Nhan3(b1) ^ b2 ^ b3);
            byte r1 = (byte)(b0 ^ Nhan2(b1) ^ Nhan3(b2) ^ b3);
            byte r2 = (byte)(b0 ^ b1 ^ Nhan2(b2) ^ Nhan3(b3));
            byte r3 = (byte)(Nhan3(b0) ^ b1 ^ b2 ^ Nhan2(b3));

            kq[i] = (uint)(r0 << 24 | r1 << 16 | r2 << 8 | r3);
        }
        return kq;
    }

    // Hiển thị ma trận
    public static void ShowMatrix(uint[] w)
    {
        for (int i = 0; i < 4; i++)
        {
            Console.WriteLine();
            Console.Write("\t");
            ShowWord(w[i]);
        }
    }

    // Mã hóa AES
    public static uint[] MahoaAES(uint[] state, uint[] key)
    {
        uint[] w = KeyExpansion(key);
        state = AddRoundKey(state, w, 0);
        for (int j = 1; j <= 13; j++) // Tăng từ 9 lên 13 vòng
        {
            state = SubBytes(state);
            state = ShiftRows(state);
            state = MixColumns(state);
            state = AddRoundKey(state, w, j);
        }
        // Vòng thứ 14
        state = SubBytes(state);
        state = ShiftRows(state);
        state = AddRoundKey(state, w, 14);
        return state;
    }


    // Dịch chuyển hàng ngược
    public static uint[] InvShiftRows(uint[] state)
    {
        uint[] kq = new uint[4];
        for (int i = 0; i < 4; i++)
        {
            uint byte1 = (state[i] & 0xFF000000) >> 24;
            uint byte2 = (state[(i + 3) % 4] & 0x00FF0000) >> 16;
            uint byte3 = (state[(i + 2) % 4] & 0x0000FF00) >> 8;
            uint byte4 = state[(i + 1) % 4] & 0x000000FF;
            kq[i] = (byte1 << 24) | (byte2 << 16) | (byte3 << 8) | byte4;
        }
        return kq;
    }

    // Thay thế ngược bằng InvS-box
    public static uint InvSubWord(uint w)
    {
        uint kq = 0;
        for (int i = 0; i < 4; i++)
        {
            byte b = (byte)((w >> (24 - i * 8)) & 0xFF);
            byte subB = InvSBox[b];
            kq = (kq << 8) | subB;
        }
        return kq;
    }

    public static uint[] InvSubBytes(uint[] state)
    {
        uint[] kq = new uint[4];
        for (int i = 0; i < 4; i++)
        {
            kq[i] = InvSubWord(state[i]);
        }
        return kq;
    }

    // Trộn cột ngược
    public static uint[] InvMixColumns(uint[] state)
    {
        uint[] kq = new uint[4];
        for (int i = 0; i < 4; i++)
        {
            byte b0 = (byte)((state[i] >> 24) & 0xFF);
            byte b1 = (byte)((state[i] >> 16) & 0xFF);
            byte b2 = (byte)((state[i] >> 8) & 0xFF);
            byte b3 = (byte)(state[i] & 0xFF);

            byte r0 = (byte)(NhanE(b0) ^ NhanB(b1) ^ NhanD(b2) ^ Nhan9(b3));
            byte r1 = (byte)(Nhan9(b0) ^ NhanE(b1) ^ NhanB(b2) ^ NhanD(b3));
            byte r2 = (byte)(NhanD(b0) ^ Nhan9(b1) ^ NhanE(b2) ^ NhanB(b3));
            byte r3 = (byte)(NhanB(b0) ^ NhanD(b1) ^ Nhan9(b2) ^ NhanE(b3));

            kq[i] = (uint)(r0 << 24 | r1 << 16 | r2 << 8 | r3);
        }
        return kq;
    }

    // Giải mã AES
    public static uint[] GiaimaAES(uint[] C, uint[] key)
    {
        uint[] w = KeyExpansion(key);
        uint[] state = AddRoundKey(C, w, 14); // Đổi từ 10 thành 14
        for (int j = 13; j >= 1; j--) // Đổi từ 9 thành 13
        {
            state = InvShiftRows(state);
            state = InvSubBytes(state);
            state = AddRoundKey(state, w, j);
            state = InvMixColumns(state);
        }
        state = InvShiftRows(state);
        state = InvSubBytes(state);
        state = AddRoundKey(state, w, 0);
        return state;
    }
    // Thêm các hàm chuyển đổi
    public static uint[] StringToUintArray(string text)
    {
        // Chuyển string thành mảng byte
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(text);

        // Padding theo chuẩn PKCS7
        int blockSize = 16; // 128 bit = 16 byte
        int padding = blockSize - (bytes.Length % blockSize);
        byte[] paddedBytes = new byte[bytes.Length + padding];
        Array.Copy(bytes, paddedBytes, bytes.Length);
        for (int i = bytes.Length; i < paddedBytes.Length; i++)
        {
            paddedBytes[i] = (byte)padding;
        }

        // Chuyển mảng byte thành mảng uint (4 byte = 1 uint)
        uint[] result = new uint[paddedBytes.Length / 4];
        for (int i = 0; i < result.Length; i++)
        {
            result[i] = (uint)(paddedBytes[i * 4] << 24 |
                              paddedBytes[i * 4 + 1] << 16 |
                              paddedBytes[i * 4 + 2] << 8 |
                              paddedBytes[i * 4 + 3]);
        }
        return result;
    }

    public static string UintArrayToString(uint[] data)
    {
        try
        {
            // Chuyển mảng uint thành mảng byte
            byte[] bytes = new byte[data.Length * 4];
            for (int i = 0; i < data.Length; i++)
            {
                bytes[i * 4] = (byte)(data[i] >> 24);
                bytes[i * 4 + 1] = (byte)(data[i] >> 16);
                bytes[i * 4 + 2] = (byte)(data[i] >> 8);
                bytes[i * 4 + 3] = (byte)(data[i]);
            }

            // Kiểm tra và xử lý padding PKCS7
            int lastByte = bytes[bytes.Length - 1];
            if (lastByte > 0 && lastByte <= 16) // Kiểm tra giá trị padding hợp lệ
            {
                // Kiểm tra xem tất cả các byte padding có giống nhau không
                bool validPadding = true;
                for (int i = bytes.Length - lastByte; i < bytes.Length; i++)
                {
                    if (bytes[i] != lastByte)
                    {
                        validPadding = false;
                        break;
                    }
                }

                if (validPadding)
                {
                    byte[] unpaddedBytes = new byte[bytes.Length - lastByte];
                    Array.Copy(bytes, unpaddedBytes, unpaddedBytes.Length);
                    return System.Text.Encoding.UTF8.GetString(unpaddedBytes);
                }
            }

            // Nếu padding không hợp lệ, trả về toàn bộ dữ liệu
            return System.Text.Encoding.UTF8.GetString(bytes);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Lỗi khi giải mã: {ex.Message}");
            return string.Empty;
        }
    }

    // Add new helper methods
    private static uint[] GenerateRandomKey()
    {
        uint[] key = new uint[8]; // 256-bit = 8 x 32-bit words
        using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
        {
            byte[] bytes = new byte[32];
            rng.GetBytes(bytes);
            for (int i = 0; i < 8; i++)
            {
                key[i] = BitConverter.ToUInt32(bytes, i * 4);
            }
        }
        return key;
    }

    private static void PrintKey(uint[] key)
    {
        Console.WriteLine("Key (256-bit):");
        for (int i = 0; i < key.Length; i++)
        {
            Console.Write($"{key[i]:X8} ");
            if (i % 4 == 3) Console.WriteLine();
        }
    }

    public static void Main(string[] args)
    {
        // Generate a random 256-bit key
        uint[] Key = GenerateRandomKey();
        PrintKey(Key);

        // Test with multiple blocks
        string plaintext = "This is a secret message that needs strong encryption using AES-256!";
        Console.WriteLine($"\nPlaintext: {plaintext}");

        // Convert to uint array and encrypt
        uint[] state = StringToUintArray(plaintext);
        Console.WriteLine($"\nInput blocks: {state.Length}");

        // Encrypt each block
        List<uint[]> encryptedBlocks = new List<uint[]>();
        for (int i = 0; i < state.Length; i += 4)
        {
            uint[] block = new uint[4];
            Array.Copy(state, i, block, 0, 4);
            encryptedBlocks.Add(MahoaAES(block, Key));
        }

        // Display encrypted blocks
        Console.WriteLine("\nEncrypted blocks (hex):");
        foreach (var block in encryptedBlocks)
        {
            ShowMatrix(block);
            Console.WriteLine();
        }

        // Decrypt blocks
        List<uint[]> decryptedBlocks = new List<uint[]>();
        foreach (var block in encryptedBlocks)
        {
            decryptedBlocks.Add(GiaimaAES(block, Key));
        }

        // Combine decrypted blocks
        uint[] decryptedState = new uint[state.Length];
        for (int i = 0; i < decryptedBlocks.Count; i++)
        {
            Array.Copy(decryptedBlocks[i], 0, decryptedState, i * 4, 4);
        }

        // Convert back to string
        string decryptedText = UintArrayToString(decryptedState);
        Console.WriteLine($"\nDecrypted text: {decryptedText}");
    }
}
