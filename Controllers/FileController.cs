using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.IO;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Net;

namespace FileTransferWeb.Controllers
{
    public class FileController : Controller
    {
        private readonly string uploadFolder = "UploadedFiles";
        private const int MaxFileSize = 100 * 1024 * 1024; // 100MB limit
        private const int NetworkTimeout = 30000; // 30 seconds

        public FileController()
        {
            if (!Directory.Exists(uploadFolder))
                Directory.CreateDirectory(uploadFolder);
        }

        // Trang Upload File
        public IActionResult Upload()
        {
            return View();
        }

        // Xử lý Upload
        [HttpPost]
        public async Task<IActionResult> Upload(IFormFile file)
        {
            if (file != null)
            {
                if (file.Length > MaxFileSize)
                {
                    ViewBag.Message = "File quá lớn! Giới hạn 100MB.";
                    return View();
                }

                if (file.Length > 0)
                {
                    string filePath = Path.Combine(uploadFolder, file.FileName);
                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        await file.CopyToAsync(stream);
                    }
                    ViewBag.Message = "Tải file lên thành công!";
                }
            }
            else
            {
                ViewBag.Message = "Vui lòng chọn file!";
            }
            return View();
        }

        [HttpPost]
        public IActionResult SendFile(string fileName, string ip, int port)
        {
            if (!IPAddress.TryParse(ip, out _))
            {
                ViewBag.Message = "Địa chỉ IP không hợp lệ!";
                return View("Upload");
            }

            if (port < 1 || port > 65535)
            {
                ViewBag.Message = "Port không hợp lệ!";
                return View("Upload");
            }

            string filePath = Path.Combine(uploadFolder, fileName);
            if (System.IO.File.Exists(filePath))
            {
                TcpClient client = null;
                try
                {
                    // Read file and convert to uint array
                    byte[] fileBytes = System.IO.File.ReadAllBytes(filePath);
                    string fileContent = System.Text.Encoding.UTF8.GetString(fileBytes);
                    uint[] dataToEncrypt = Aes256Helper.StringToUintArray(fileContent);

                    // Generate encryption key
                    uint[] encryptionKey = new uint[8]; // 256-bit key
                    using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
                    {
                        byte[] keyBytes = new byte[32];
                        rng.GetBytes(keyBytes);
                        for (int i = 0; i < 8; i++)
                        {
                            encryptionKey[i] = BitConverter.ToUInt32(keyBytes, i * 4);
                        }
                    }

                    // Encrypt data in blocks
                    List<uint[]> encryptedBlocks = new List<uint[]>();
                    for (int i = 0; i < dataToEncrypt.Length; i += 4)
                    {
                        uint[] block = new uint[4];
                        Array.Copy(dataToEncrypt, i, block, 0, Math.Min(4, dataToEncrypt.Length - i));
                        encryptedBlocks.Add(Aes256Helper.MahoaAES(block, encryptionKey));
                    }

                    // Connect and send data
                    client = new TcpClient();
                    var result = client.BeginConnect(ip, port, null, null);
                    var success = result.AsyncWaitHandle.WaitOne(NetworkTimeout);

                    if (!success)
                    {
                        throw new SocketException();
                    }

                    using (NetworkStream stream = client.GetStream())
                    using (BinaryWriter writer = new BinaryWriter(stream))
                    {
                        writer.Write(fileName);
                        // Send encryption key first
                        foreach (uint keyPart in encryptionKey)
                        {
                            writer.Write(keyPart);
                        }
                        // Send number of blocks
                        writer.Write(encryptedBlocks.Count);
                        // Send each encrypted block
                        foreach (var block in encryptedBlocks)
                        {
                            foreach (uint value in block)
                            {
                                writer.Write(value);
                            }
                        }
                    }

                    ViewBag.Message = "File đã được gửi (đã mã hóa AES-256)!";
                }
                catch (SocketException)
                {
                    ViewBag.Message = "Lỗi kết nối: Không thể kết nối đến máy nhận!";
                }
                catch (Exception ex)
                {
                    ViewBag.Message = $"Lỗi khi gửi file: {ex.Message}";
                }
                finally
                {
                    client?.Close();
                }
            }
            else
            {
                ViewBag.Message = "File không tồn tại!";
            }
            return View("Upload");
        }

        // Nhận file
        [HttpGet]
        public IActionResult Receive()
        {
            return View();
        }

        [HttpPost]
        public IActionResult ReceiveFile(int port)
        {
            if (port < 1 || port > 65535)
            {
                ViewBag.Message = "Port không hợp lệ!";
                return View("Receive");
            }

            TcpListener listener = null;
            try
            {
                listener = new TcpListener(IPAddress.Any, port);
                listener.Start();

                using (var client = listener.AcceptTcpClient())
                {
                    client.ReceiveTimeout = NetworkTimeout;
                    client.SendTimeout = NetworkTimeout;

                    using (NetworkStream stream = client.GetStream())
                    using (BinaryReader reader = new BinaryReader(stream))
                    {
                        string fileName = reader.ReadString();

                        // Read encryption key
                        uint[] encryptionKey = new uint[8];
                        for (int i = 0; i < 8; i++)
                        {
                            encryptionKey[i] = reader.ReadUInt32();
                        }

                        // Read number of blocks
                        int blockCount = reader.ReadInt32();
                        List<uint[]> encryptedBlocks = new List<uint[]>();

                        // Read each encrypted block
                        for (int i = 0; i < blockCount; i++)
                        {
                            uint[] block = new uint[4];
                            for (int j = 0; j < 4; j++)
                            {
                                block[j] = reader.ReadUInt32();
                            }
                            encryptedBlocks.Add(block);
                        }

                        // Decrypt blocks
                        List<uint[]> decryptedBlocks = new List<uint[]>();
                        foreach (var block in encryptedBlocks)
                        {
                            decryptedBlocks.Add(Aes256Helper.GiaimaAES(block, encryptionKey));
                        }

                        // Combine all decrypted blocks
                        uint[] decryptedData = new uint[decryptedBlocks.Count * 4];
                        for (int i = 0; i < decryptedBlocks.Count; i++)
                        {
                            Array.Copy(decryptedBlocks[i], 0, decryptedData, i * 4, 4);
                        }

                        // Convert back to string and then to bytes
                        string decryptedText = Aes256Helper.UintArrayToString(decryptedData);
                        byte[] decryptedBytes = System.Text.Encoding.UTF8.GetBytes(decryptedText);

                        string savePath = Path.Combine(uploadFolder, "decrypted_" + fileName);
                        System.IO.File.WriteAllBytes(savePath, decryptedBytes);
                    }
                }

                ViewBag.Message = "Đã nhận và giải mã file thành công!";
            }
            catch (Exception ex)
            {
                ViewBag.Message = $"Lỗi khi nhận file: {ex.Message}";
            }
            finally
            {
                listener?.Stop();
            }
            return View("Receive");
        }
    }
}
