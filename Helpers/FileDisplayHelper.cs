namespace SecureDataSharing.Helpers
{
    public class FileDisplayHelper
    {
        public static string GetFileIconClass(string? contentType, string? fileName)
        {
            if (string.IsNullOrEmpty(contentType) && string.IsNullOrEmpty(fileName))
            {
                return "fas fa-file";
            }

            if (!string.IsNullOrEmpty(contentType))
            {
                if (contentType.StartsWith("image/")) return "fas fa-file-image";
                if (contentType.Equals("application/pdf")) return "fas fa-file-pdf";
                if (contentType.Equals("application/msword") || contentType.Equals("application/vnd.openxmlformats-officedocument.wordprocessingml.document")) return "fas fa-file-word";
                if (contentType.Equals("application/vnd.ms-excel") || contentType.Equals("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")) return "fas fa-file-excel";
                if (contentType.Equals("application/vnd.ms-powerpoint") || contentType.Equals("application/vnd.openxmlformats-officedocument.presentationml.presentation")) return "fas fa-file-powerpoint";
                if (contentType.StartsWith("audio/")) return "fas fa-file-audio";
                if (contentType.StartsWith("video/")) return "fas fa-file-video";
                if (contentType.Equals("application/zip") || contentType.Equals("application/x-rar-compressed")) return "fas fa-file-archive";
                if (contentType.Equals("text/plain")) return "fas fa-file-alt";
            }

            // Якщо тип не визначено, спробуємо за розширенням файлу
            if (!string.IsNullOrEmpty(fileName))
            {
                string extension = Path.GetExtension(fileName).ToLowerInvariant();
                switch (extension)
                {
                    case ".txt": return "fas fa-file-alt";
                    case ".doc": case ".docx": return "fas fa-file-word";
                    case ".xls": case ".xlsx": return "fas fa-file-excel";
                    case ".ppt": case ".pptx": return "fas fa-file-powerpoint";
                    case ".pdf": return "fas fa-file-pdf";
                    case ".jpg": case ".jpeg": case ".png": case ".gif": case ".bmp": return "fas fa-file-image";
                    case ".zip": case ".rar": case ".7z": return "fas fa-file-archive";
                }
            }
            return "fas fa-file";
        }

        public static string FormatFileSize(long? bytes)
        {
            if (bytes == null) return string.Empty;
            if (bytes == 0) return "0 B";

            const int k = 1024;
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int i = (int)Math.Floor(Math.Log(bytes.Value) / Math.Log(k));
            return string.Format("{0:0.##} {1}", bytes.Value / Math.Pow(k, i), sizes[i]);
        }
    }
}
