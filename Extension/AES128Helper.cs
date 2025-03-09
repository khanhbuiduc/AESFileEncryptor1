using System;

public class AES128Helper
{
    // S-box cho SubBytes
    private static readonly byte[] sBox = new byte[]
    {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
        0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
        0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
        0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
        0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
        0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
        0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
        0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
        0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
        0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
        0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
        0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
        0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
        0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
        0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };

    // Inverse S-box cho InvSubBytes
    private static readonly byte[] invSBox = new byte[]
    {
        0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
        0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
        0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
        0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
        0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
        0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
        0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
        0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
        0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
        0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
        0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
        0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
        0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
        0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
        0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
        0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
    };

    // Mảng Rcon cho quá trình mở rộng khóa
    private static readonly byte[] Rcon = new byte[]
    {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };

    // Hàm tiện ích: ShowWord trả về chuỗi hex 8 ký tự của một từ 32-bit
    public static string ShowWord(uint w)
    {
        return w.ToString("X8");
    }

    // RotWord: xoay vòng từ 32-bit sang trái 8 bit (1 byte)
    public static uint RotWord(uint w)
    {
        return (w << 8) | (w >> 24);
    }

    // SubWord: thay thế mỗi byte trong từ bằng giá trị từ S-box
    public static uint SubWord(uint w)
    {
        uint result = 0;
        for (int i = 0; i < 4; i++)
        {
            byte b = (byte)(w >> (24 - i * 8));
            byte sub = sBox[b];
            result |= (uint)sub << (24 - i * 8);
        }
        return result;
    }

    // XorRcon: XOR byte đầu tiên của từ với giá trị Rcon của vòng j
    public static uint XorRcon(uint w, int j)
    {
        byte rconVal = Rcon[j];
        byte first = (byte)(w >> 24);
        first ^= rconVal;
        uint result = (uint)first << 24;
        result |= w & 0x00FFFFFF;
        return result;
    }

    // G: hàm hỗ trợ trong KeyExpansion, gồm RotWord, SubWord và XOR với Rcon
    public static uint G(uint w, int j)
    {
        uint rotW = RotWord(w);
        uint subW = SubWord(rotW);
        return XorRcon(subW, j);
    }

    // KeyExpansion: mở rộng khóa 128-bit (4 từ) thành 44 từ
    public static uint[] KeyExpansion(uint[] key)
    {
        if (key.Length != 4)
            throw new ArgumentException("Key phải có 4 từ cho AES-128.");
        uint[] w = new uint[44];
        for (int i = 0; i < 4; i++)
            w[i] = key[i];
        for (int i = 4; i < 44; i++)
        {
            uint temp = w[i - 1];
            if (i % 4 == 0)
                temp = G(temp, i / 4);
            w[i] = w[i - 4] ^ temp;
        }
        return w;
    }

    // AddRoundKey: XOR trạng thái với khóa vòng (state và roundKey có 4 từ)
    public static uint[] AddRoundKey(uint[] state, uint[] roundKey)
    {
        if (state.Length != 4 || roundKey.Length != 4)
            throw new ArgumentException("State và roundKey phải có 4 từ.");
        uint[] result = new uint[4];
        for (int i = 0; i < 4; i++)
            result[i] = state[i] ^ roundKey[i];
        return result;
    }

    // SubBytes: áp dụng S-box cho mỗi byte trong state
    public static uint[] SubBytes(uint[] state)
    {
        uint[] result = new uint[4];
        for (int i = 0; i < 4; i++)
            result[i] = SubWord(state[i]);
        return result;
    }

    // InvSubBytes: áp dụng inverse S-box cho mỗi byte trong state
    public static uint[] InvSubBytes(uint[] state)
    {
        uint[] result = new uint[4];
        for (int i = 0; i < 4; i++)
        {
            uint word = state[i];
            uint newWord = 0;
            for (int j = 0; j < 4; j++)
            {
                byte b = (byte)(word >> (24 - j * 8));
                byte sub = invSBox[b];
                newWord |= (uint)sub << (24 - j * 8);
            }
            result[i] = newWord;
        }
        return result;
    }

    // ShiftRows: dịch chuyển các hàng của state (state được biểu diễn dưới dạng 4 từ, mỗi từ là một cột)
    public static uint[] ShiftRows(uint[] state)
    {
        byte[,] matrix = StateToMatrix(state);
        // Hàng 0 không dịch
        for (int i = 1; i < 4; i++)
            matrix = ShiftRow(matrix, i, i);
        return MatrixToState(matrix);
    }

    // InvShiftRows: dịch chuyển ngược lại các hàng của state
    public static uint[] InvShiftRows(uint[] state)
    {
        byte[,] matrix = StateToMatrix(state);
        for (int i = 1; i < 4; i++)
            matrix = ShiftRow(matrix, i, 4 - i);
        return MatrixToState(matrix);
    }

    // Chuyển state (4 từ) thành ma trận 4x4 byte (theo thứ tự cột)
    public static byte[,] StateToMatrix(uint[] state)
    {
        byte[,] matrix = new byte[4, 4];
        for (int col = 0; col < 4; col++)
        {
            uint word = state[col];
            for (int row = 0; row < 4; row++)
                matrix[row, col] = (byte)(word >> (24 - row * 8));
        }
        return matrix;
    }

    // Chuyển ma trận 4x4 byte thành state (4 từ) theo thứ tự cột
    public static uint[] MatrixToState(byte[,] matrix)
    {
        uint[] state = new uint[4];
        for (int col = 0; col < 4; col++)
        {
            uint word = 0;
            for (int row = 0; row < 4; row++)
                word |= (uint)matrix[row, col] << (24 - row * 8);
            state[col] = word;
        }
        return state;
    }

    // Dịch một hàng trong ma trận sang trái theo số vị trí xác định
    public static byte[,] ShiftRow(byte[,] matrix, int row, int shift)
    {
        byte[] temp = new byte[4];
        for (int col = 0; col < 4; col++)
            temp[col] = matrix[row, col];
        byte[] shifted = new byte[4];
        for (int col = 0; col < 4; col++)
            shifted[col] = temp[(col + shift) % 4];
        for (int col = 0; col < 4; col++)
            matrix[row, col] = shifted[col];
        return matrix;
    }

    // Nhân một byte với 2 trong GF(2^8)
    public static byte MultiplyBy2(byte b)
    {
        int res = b << 1;
        if ((b & 0x80) != 0)
            res ^= 0x1B;
        return (byte)(res & 0xFF);
    }

    // Nhân một byte với 3: 3*b = 2*b XOR b
    public static byte MultiplyBy3(byte b)
    {
        return (byte)(MultiplyBy2(b) ^ b);
    }

    // Hàm nhân 2 byte trong GF(2^8)
    public static byte Multiply(byte a, byte b)
    {
        byte result = 0;
        for (int i = 0; i < 8; i++)
        {
            if ((b & 1) != 0)
                result ^= a;
            bool highBit = (a & 0x80) != 0;
            a <<= 1;
            if (highBit)
                a ^= 0x1B;
            b >>= 1;
        }
        return result;
    }

    // MixColumns: trộn các cột của state theo ma trận cố định
    public static uint[] MixColumns(uint[] state)
    {
        byte[,] matrix = StateToMatrix(state);
        for (int col = 0; col < 4; col++)
        {
            byte s0 = matrix[0, col];
            byte s1 = matrix[1, col];
            byte s2 = matrix[2, col];
            byte s3 = matrix[3, col];
            byte r0 = (byte)(MultiplyBy2(s0) ^ MultiplyBy3(s1) ^ s2 ^ s3);
            byte r1 = (byte)(s0 ^ MultiplyBy2(s1) ^ MultiplyBy3(s2) ^ s3);
            byte r2 = (byte)(s0 ^ s1 ^ MultiplyBy2(s2) ^ MultiplyBy3(s3));
            byte r3 = (byte)(MultiplyBy3(s0) ^ s1 ^ s2 ^ MultiplyBy2(s3));
            matrix[0, col] = r0;
            matrix[1, col] = r1;
            matrix[2, col] = r2;
            matrix[3, col] = r3;
        }
        return MatrixToState(matrix);
    }

    // InvMixColumns: giải trộn các cột của state
    public static uint[] InvMixColumns(uint[] state)
    {
        byte[,] matrix = StateToMatrix(state);
        for (int col = 0; col < 4; col++)
        {
            byte s0 = matrix[0, col];
            byte s1 = matrix[1, col];
            byte s2 = matrix[2, col];
            byte s3 = matrix[3, col];
            byte r0 = (byte)(Multiply(s0, 0x0e) ^ Multiply(s1, 0x0b) ^ Multiply(s2, 0x0d) ^ Multiply(s3, 0x09));
            byte r1 = (byte)(Multiply(s0, 0x09) ^ Multiply(s1, 0x0e) ^ Multiply(s2, 0x0b) ^ Multiply(s3, 0x0d));
            byte r2 = (byte)(Multiply(s0, 0x0d) ^ Multiply(s1, 0x09) ^ Multiply(s2, 0x0e) ^ Multiply(s3, 0x0b));
            byte r3 = (byte)(Multiply(s0, 0x0b) ^ Multiply(s1, 0x0d) ^ Multiply(s2, 0x09) ^ Multiply(s3, 0x0e));
            matrix[0, col] = r0;
            matrix[1, col] = r1;
            matrix[2, col] = r2;
            matrix[3, col] = r3;
        }
        return MatrixToState(matrix);
    }

    // Encrypt: mã hóa một khối 128-bit (state gồm 4 từ) với khóa 128-bit (4 từ)
    public static uint[] Encrypt(uint[] inputState, uint[] key)
    {
        uint[] w = KeyExpansion(key);
        uint[] state = AddRoundKey(inputState, new uint[] { w[0], w[1], w[2], w[3] });
        for (int round = 1; round <= 9; round++)
        {
            state = SubBytes(state);
            state = ShiftRows(state);
            state = MixColumns(state);
            state = AddRoundKey(state, new uint[]
            {
                w[4 * round], w[4 * round + 1],
                w[4 * round + 2], w[4 * round + 3]
            });
        }
        state = SubBytes(state);
        state = ShiftRows(state);
        state = AddRoundKey(state, new uint[] { w[40], w[41], w[42], w[43] });
        return state;
    }

    // Decrypt: giải mã một khối 128-bit với khóa 128-bit
    public static uint[] Decrypt(uint[] inputState, uint[] key)
    {
        uint[] w = KeyExpansion(key);
        uint[] state = AddRoundKey(inputState, new uint[] { w[40], w[41], w[42], w[43] });
        state = InvShiftRows(state);
        state = InvSubBytes(state);
        for (int round = 9; round >= 1; round--)
        {
            state = AddRoundKey(state, new uint[]
            {
                w[4 * round], w[4 * round + 1],
                w[4 * round + 2], w[4 * round + 3]
            });
            state = InvMixColumns(state);
            state = InvShiftRows(state);
            state = InvSubBytes(state);
        }
        state = AddRoundKey(state, new uint[] { w[0], w[1], w[2], w[3] });
        return state;
    }

    // Hiển thị state dưới dạng 4 từ hex
    public static void ShowMatrix(uint[] state)
    {
        for (int i = 0; i < state.Length; i++)
            Console.WriteLine(ShowWord(state[i]));
    }

    // Hàm main để kiểm thử mã hóa và giải mã
    public static void Main(string[] args)
    {
        // Khóa ví dụ: 0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c
        uint[] key = new uint[] { 0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c };
        // Plaintext ví dụ: 0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734
        uint[] plaintext = new uint[] { 0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734 };

        Console.WriteLine("Plaintext:");
        ShowMatrix(plaintext);

        uint[] ciphertext = Encrypt(plaintext, key);
        Console.WriteLine("\nCiphertext:");
        ShowMatrix(ciphertext);

        uint[] decrypted = Decrypt(ciphertext, key);
        Console.WriteLine("\nDecrypted:");
        ShowMatrix(decrypted);
    }
}
