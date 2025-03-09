using System;

public static class AES128Helper
{
    private static readonly uint[] Key = new uint[]
    {
        0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c
    };

    private static uint RotWord(uint w) => (w << 8) | (w >> 24);

    private static uint SubWord(uint w)
    {
        int[] S = new int[]
        {
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75
        };

        uint kq = 0;
        for (int i = 0; i < 4; i++)
        {
            byte b = (byte)((w >> (24 - i * 8)) & 0xFF);
            kq = (kq << 8) | (uint)S[b];
        }
        return kq;
    }

    private static uint XorRcon(uint w, int j)
    {
        int[] Rc = new int[]
        {
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
        };
        return w ^ (uint)(Rc[j] << 24);
    }

    private static uint[] KeyExpansion()
    {
        uint[] w = new uint[44];
        Array.Copy(Key, w, 4);

        for (int i = 4; i < 44; i++)
        {
            if (i % 4 == 0)
                w[i] = w[i - 4] ^ XorRcon(SubWord(RotWord(w[i - 1])), i / 4);
            else
                w[i] = w[i - 4] ^ w[i - 1];
        }
        return w;
    }

    private static uint[] AddRoundKey(uint[] state, uint[] key, int round)
    {
        for (int i = 0; i < 4; i++)
            state[i] ^= key[round * 4 + i];
        return state;
    }

    private static uint[] SubBytes(uint[] state)
    {
        for (int i = 0; i < 4; i++)
            state[i] = SubWord(state[i]);
        return state;
    }

    private static uint[] ShiftRows(uint[] state)
    {
        return new uint[]
        {
            state[0],
            (state[1] << 8) | (state[1] >> 24),
            (state[2] << 16) | (state[2] >> 16),
            (state[3] << 24) | (state[3] >> 8)
        };
    }

    public static uint[] Encrypt(uint[] plaintext)
    {
        uint[] w = KeyExpansion();
        uint[] state = AddRoundKey(plaintext, w, 0);

        for (int round = 1; round <= 9; round++)
        {
            state = SubBytes(state);
            state = ShiftRows(state);
            state = AddRoundKey(state, w, round);
        }

        state = SubBytes(state);
        state = ShiftRows(state);
        state = AddRoundKey(state, w, 10);

        return state;
    }

    public static uint[] Decrypt(uint[] ciphertext)
    {
        uint[] w = KeyExpansion();
        uint[] state = AddRoundKey(ciphertext, w, 10);

        for (int round = 9; round >= 1; round--)
        {
            state = ShiftRows(state);
            state = SubBytes(state);
            state = AddRoundKey(state, w, round);
        }

        state = ShiftRows(state);
        state = SubBytes(state);
        state = AddRoundKey(state, w, 0);

        return state;
    }
}
