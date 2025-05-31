namespace SecureDataSharing.Models
{
    public class StoredDataIndexViewModel
    {
        public int Id { get; set; }
        public string? DataName { get; set; } // Буде використовуватися як мітка/опис
        public DateTime Timestamp { get; set; }
        public bool IsOwner { get; set; }
        public string? OwnerEmail { get; set; }
        public StorageEntryType DataType { get; set; } // Тип: Текст чи Файл
        public string? OriginalFileName { get; set; }   // Для файлів
        public long? FileSize { get; set; }             // Для файлів
        public string? ContentType { get; set; }        // Для файлів (для іконки)
    }
}
