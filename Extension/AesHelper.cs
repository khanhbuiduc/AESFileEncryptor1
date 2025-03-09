using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public static class AesHelper
{
    private static readonly string Key = "0123456789abcdef0123456789abcdef"; // 32 byte
    private static readonly string IV = "abcdef9876543210"; // 16 byte

    public static byte[] Encrypt(byte[] data)
    {
        using Aes aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(Key);
        aes.IV = Encoding.UTF8.GetBytes(IV);

        using MemoryStream ms = new MemoryStream();
        using CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
        cs.Write(data, 0, data.Length);
        cs.FlushFinalBlock();

        return ms.ToArray();
    }

    public static byte[] Decrypt(byte[] data)
    {
        using Aes aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(Key);
        aes.IV = Encoding.UTF8.GetBytes(IV);

        using MemoryStream ms = new MemoryStream(data);
        using CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using MemoryStream output = new MemoryStream();
        cs.CopyTo(output);

        return output.ToArray();
    }
}
