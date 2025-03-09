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
                    byte[] fileBytes = System.IO.File.ReadAllBytes(filePath);
                    byte[] encryptedData = AesHelper.Encrypt(fileBytes);

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
                        writer.Write(encryptedData.Length);
                        writer.Write(encryptedData);
                    }

                    ViewBag.Message = "File đã được gửi (đã mã hóa)!";
                }
                catch (SocketException)
                {
                    ViewBag.Message = "Lỗi kết nối: Không thể kết nối đến máy nhận!";
                }
                catch (Exception)
                {
                    ViewBag.Message = "Lỗi khi gửi file!";
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
                        int dataSize = reader.ReadInt32();

                        if (dataSize > MaxFileSize)
                        {
                            throw new Exception("File quá lớn!");
                        }

                        byte[] encryptedData = reader.ReadBytes(dataSize);
                        byte[] decryptedData = AesHelper.Decrypt(encryptedData);

                        string savePath = Path.Combine(uploadFolder, "decrypted_" + fileName);
                        System.IO.File.WriteAllBytes(savePath, decryptedData);
                    }
                }

                ViewBag.Message = "Đã nhận và giải mã file!";
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
