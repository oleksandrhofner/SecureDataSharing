using System.ComponentModel.DataAnnotations;

namespace SecureDataSharing.Models
{
    public class EditDataViewModel
    {
        public int Id { get; set; }

        [Required(ErrorMessage = "Будь ласка, введіть назву запису.")]
        [StringLength(200)]
        [Display(Name = "Назва запису")]
        public string? DataName { get; set; }

        public StorageEntryType DataType { get; set; } // Для відображення, не редагується тут
        public string? OriginalFileName { get; set; } // Для відображення, якщо це файл
        public string? ContentType { get; set; }      // Для відображення, якщо це файл

        [Display(Name = "Вміст тексту")] // Буде заповнено з TempData або введено користувачем
        public string? TextContent { get; set; }

        [Display(Name = "Завантажити новий файл (якщо замінюєте файл)")]
        public IFormFile? NewFileToUpload { get; set; }

        [Required(ErrorMessage = "Будь ласка, введіть ваш поточний пароль для збереження змін.")]
        [DataType(System.ComponentModel.DataAnnotations.DataType.Password)]
        [Display(Name = "Ваш пароль (для збереження)")]
        public string? UserPasswordForSave { get; set; }

        public string? ErrorMessage { get; set; } // Для відображення помилок на сторінці Edit
    }
}
