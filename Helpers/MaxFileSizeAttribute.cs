using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;

namespace SecureDataSharing.Helpers
{
    public class MaxFileSizeAttribute : ValidationAttribute
    {
        private readonly long _maxFileSizeInBytes;
        public MaxFileSizeAttribute(int maxFileSizeInMegabytes)
        {
            _maxFileSizeInBytes = (long)maxFileSizeInMegabytes * 1024L * 1024L;
        }

        protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
        {
            if (value is IFormFile file)
            {
                // Додамо перевірку, що файл взагалі має вміст, 
                if (file.Length > 0 && file.Length > _maxFileSizeInBytes)
                {
                    return new ValidationResult(GetErrorMessage());
                }
            }
            return ValidationResult.Success;
        }

        public string GetErrorMessage()
        {
            return $"Максимальний дозволений розмір файлу - {_maxFileSizeInBytes / (1024L * 1024L)} MB.";
        }
    }
}
