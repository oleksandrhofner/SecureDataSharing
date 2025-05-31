namespace SecureDataSharing.Models
{
    public class DetailsViewModel
    {
        public int Id { get; set; }
        public string? DataName { get; set; }
        public DateTime Timestamp { get; set; }
        public StorageEntryType DataType { get; set; }
        public string? OriginalFileName { get; set; }
        public string? ContentType { get; set; }
        public long? FileSize { get; set; }
        public string? DecryptedText { get; set; } // Розшифрований текст
        public bool UserHasPermission { get; set; } // Чи має користувач взагалі доступ (власник або отримувач)
        public bool IsOwner { get; set; }
        public bool RequirePasswordPrompt { get; set; } // Чи потрібно показувати форму введення пароля
        public string? ErrorMessage { get; set; } // Для повідомлень про помилки
    }
}
