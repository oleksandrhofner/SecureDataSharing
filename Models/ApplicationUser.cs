using Microsoft.AspNetCore.Identity;
namespace SecureDataSharing.Models
{
    public class ApplicationUser : IdentityUser
    {
        //Публічний RSA ключ користувача у форматі PEM
        public string? PublicKeyPem { get; set; }
        //Зашифрований приватний RSA ключ користувача
        //Приватний ключ шифрується симетрично за допомогою ключа, похідного від пароля користувача.
        public string? EncryptedPrivateKeyPem { get; set; } // Зберігатимемо PEM-рядок, зашифрований

        //Сіль, використовується для генерації ключа шифрування приватного ключа з пароля користувача
        //Зберігається у форматі Base64.
        public string? PrivateKeyEncryptionSalt { get; set; }
    }
}
