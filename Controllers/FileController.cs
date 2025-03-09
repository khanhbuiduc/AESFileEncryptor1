using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.IO;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace FileTransferWeb.Controllers
{
    public class FileController : Controller
    {
        private readonly string uploadFolder = "UploadedFiles";

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
            if (file != null && file.Length > 0)
            {
                string filePath = Path.Combine(uploadFolder, file.FileName);
                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }
                ViewBag.Message = "Tải file lên thành công!";
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
            string filePath = Path.Combine(uploadFolder, fileName);
            if (System.IO.File.Exists(filePath))
            {
                try
                {
                    byte[] fileBytes = System.IO.File.ReadAllBytes(filePath);
                    uint[] dataBlocks = ConvertToUintArray(fileBytes);
                    uint[] encryptedData = AES128Helper.Encrypt(dataBlocks);

                    TcpClient client = new TcpClient(ip, port);
                    using NetworkStream stream = client.GetStream();
                    using BinaryWriter writer = new BinaryWriter(stream);

                    writer.Write(fileName);
                    writer.Write(encryptedData.Length);
                    foreach (uint block in encryptedData)
                        writer.Write(block);

                    client.Close();
                    ViewBag.Message = "File đã được gửi (đã mã hóa)!";
                }
                catch
                {
                    ViewBag.Message = "Lỗi khi gửi file!";
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
            try
            {
                TcpListener listener = new TcpListener(System.Net.IPAddress.Any, port);
                listener.Start();

                using TcpClient client = listener.AcceptTcpClient();
                using NetworkStream stream = client.GetStream();
                using BinaryReader reader = new BinaryReader(stream);

                string fileName = reader.ReadString();
                int dataSize = reader.ReadInt32();

                uint[] encryptedData = new uint[dataSize];
                for (int i = 0; i < dataSize; i++)
                    encryptedData[i] = reader.ReadUInt32();

                uint[] decryptedData = AES128Helper.Decrypt(encryptedData);
                byte[] fileBytes = ConvertToByteArray(decryptedData);

                string savePath = Path.Combine(uploadFolder, "decrypted_" + fileName);
                System.IO.File.WriteAllBytes(savePath, fileBytes);

                listener.Stop();
                ViewBag.Message = "Đã nhận và giải mã file!";
            }
            catch
            {
                ViewBag.Message = "Lỗi khi nhận file!";
            }
            return View("Receive");
        }
        public static uint[] ConvertToUintArray(byte[] data)
        {
            int length = (data.Length + 3) / 4; // Chia thành các khối 4 byte
            uint[] uintArray = new uint[length];

            for (int i = 0; i < data.Length; i++)
            {
                int index = i / 4;
                uintArray[index] |= (uint)(data[i] << (24 - (i % 4) * 8)); // Ghép 4 byte thành 1 uint
            }

            return uintArray;
        }
        public static byte[] ConvertToByteArray(uint[] uintArray)
        {
            byte[] byteArray = new byte[uintArray.Length * 4];

            for (int i = 0; i < uintArray.Length; i++)
            {
                byteArray[i * 4] = (byte)((uintArray[i] >> 24) & 0xFF);
                byteArray[i * 4 + 1] = (byte)((uintArray[i] >> 16) & 0xFF);
                byteArray[i * 4 + 2] = (byte)((uintArray[i] >> 8) & 0xFF);
                byteArray[i * 4 + 3] = (byte)(uintArray[i] & 0xFF);
            }

            return byteArray;
        }


    }
}
