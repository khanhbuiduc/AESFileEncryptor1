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

        // Gửi file qua mạng
        [HttpPost]
        public IActionResult SendFile(string fileName, string ip, int port)
        {
            string filePath = Path.Combine(uploadFolder, fileName);
            if (System.IO.File.Exists(filePath))
            {
                try
                {
                    TcpClient client = new TcpClient(ip, port);
                    using (NetworkStream stream = client.GetStream())
                    using (FileStream fs = new FileStream(filePath, FileMode.Open))
                    {
                        fs.CopyTo(stream);
                    }
                    client.Close();
                    ViewBag.Message = "File đã được gửi!";
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
            string savePath = Path.Combine(uploadFolder, "received_file.txt");
            try
            {
                TcpListener listener = new TcpListener(System.Net.IPAddress.Any, port);
                listener.Start();
                using (TcpClient client = listener.AcceptTcpClient())
                using (NetworkStream stream = client.GetStream())
                using (FileStream fs = new FileStream(savePath, FileMode.Create))
                {
                    stream.CopyTo(fs);
                }
                listener.Stop();
                ViewBag.Message = "Đã nhận file!";
            }
            catch
            {
                ViewBag.Message = "Lỗi khi nhận file!";
            }
            return View("Receive");
        }
    }
}
