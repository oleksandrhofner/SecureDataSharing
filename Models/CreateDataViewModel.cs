using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;
using SecureDataSharing.Helpers;

namespace SecureDataSharing.Models
{
    public class CreateDataViewModel
    {
        [Required(ErrorMessage = "Будь ласка, введіть назву запису.")]
        [StringLength(200)]
        [Display(Name = "Назва запису")]
        public string? DataName { get; set; }

        [Required(ErrorMessage = "Будь ласка, виберіть тип запису.")]
        [Display(Name = "Тип запису")]
        public StorageEntryType DataType { get; set; }

        [Display(Name = "Текстові дані")]
        public string? PlainTextData { get; set; }

        [Display(Name = "Виберіть файл")]
        [MaxFileSize(2048)] // 2048 MB = 2GB
        public IFormFile? FileToUpload { get; set; }

        [Required(ErrorMessage = "Будь ласка, введіть ваш поточний пароль для підтвердження.")]
        [DataType(System.ComponentModel.DataAnnotations.DataType.Password)]
        [Display(Name = "Ваш поточний пароль")]
        public string? UserPassword { get; set; }
    }
}