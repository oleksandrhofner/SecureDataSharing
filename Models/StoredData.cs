using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
namespace SecureDataSharing.Models
{
    public enum StorageEntryType { Text = 1, File = 2 }
    public class StoredData
    {
        [Key]
        public int Id { get; set; }
        [Required]
        public string? OwnerUserId { get; set; }
        [ForeignKey("OwnerUserId")]
        public virtual ApplicationUser? OwnerUser { get; set; }
        [Required]
        [StringLength(200)]
        [Display(Name = "Назва запису")]
        public string? DataName { get; set; }
        [Required]
        [Display(Name = "Тип запису")]
        public StorageEntryType DataType { get; set; }
        //Спільне поле для зашифрованого вмісту (текст або файл)
        //Зашифровані байти (тексту або файлу)
        //Буде VARBINARY(MAX) у базі даних
        public byte[]? EncryptedContentBytes { get; set; }
        //Метадані для файлів
        [StringLength(255)]
        [Display(Name = "Оригінальне ім'я файлу")]
        public string? OriginalFileName { get; set; }

        [StringLength(100)]
        [Display(Name = "Тип вмісту (MIME)")]
        public string? ContentType { get; set; }

        [Display(Name = "Розмір файлу (байти)")]
        public long? FileSize { get; set; }
        // --- Спільні криптографічні поля для DEK та IV
        [Required]
        public byte[]? EncryptedDekForOwner { get; set; }
        [Required]
        public byte[]? InitializationVector { get; set; } // IV для шифрування EncryptedContentBytes
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }
}
