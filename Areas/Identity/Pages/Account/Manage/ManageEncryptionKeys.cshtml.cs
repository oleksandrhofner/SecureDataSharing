using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using SecureDataSharing.Models;
using SecureDataSharing.Models.Enums;
using SecureDataSharing.Services;
using System;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureDataSharing.Areas.Identity.Pages.Account.Manage
{
    public class ManageEncryptionKeysModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager; // Може знадобитися для оновлення сесії
        private readonly ICryptographyService _cryptographyService;
        private readonly IAuditService _auditService;
        private readonly ILogger<ManageEncryptionKeysModel> _logger;

        public ManageEncryptionKeysModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ICryptographyService cryptographyService,
            IAuditService auditService,
            ILogger<ManageEncryptionKeysModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _cryptographyService = cryptographyService;
            _auditService = auditService;
            _logger = logger;
        }

        [TempData]
        public string StatusMessage { get; set; }

        public bool HasActiveKeys { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            HasActiveKeys = !string.IsNullOrEmpty(user.PublicKeyPem);
            return Page();
        }

        public async Task<IActionResult> OnPostGenerateNewKeysAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                StatusMessage = "Помилка: Не вдалося завантажити дані користувача.";
                return RedirectToPage();
            }

            _logger.LogInformation("User {UserId} initiated generation of new encryption keys.", user.Id);

            RSA? rsaKeyContainer = null; // Для Dispose
            try
            {
                // 1. Генеруємо RSA пару ключів
                var (publicKeyRsa, privateKeyRsa) = _cryptographyService.GenerateRsaKeyPair();
                rsaKeyContainer = privateKeyRsa; // Зберігаємо для Dispose

                string newPublicKeyPem = _cryptographyService.ExportPublicKeyToPem(publicKeyRsa);
                string newPrivateKeyPem = _cryptographyService.ExportPrivateKeyToPem(privateKeyRsa);

                // 2. Генеруємо НОВУ сіль для шифрування приватного ключа
                byte[] newPkEncryptionSaltBytes = _cryptographyService.GenerateSalt();
                string newPrivateKeyEncryptionSaltBase64 = Convert.ToBase64String(newPkEncryptionSaltBytes);

                // 3. Генеруємо ключ для шифрування приватного ключа з ПОТОЧНОГО пароля користувача        
                if (string.IsNullOrEmpty(Input.CurrentPasswordForNewKeys))
                {
                    StatusMessage = "Помилка: Для генерації нових ключів потрібен ваш поточний пароль.";
                    await _auditService.LogEventAsync(user.Id, user.Email, AuditEventType.UserCryptoKeysGenerationFailed,
                       "Спроба генерації нових ключів без надання пароля.", ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString());
                    return RedirectToPage();
                }

                var passwordCheck = await _userManager.CheckPasswordAsync(user, Input.CurrentPasswordForNewKeys);
                if (!passwordCheck)
                {
                    StatusMessage = "Помилка: Неправильний поточний пароль.";
                    await _auditService.LogEventAsync(user.Id, user.Email, AuditEventType.UserCryptoKeysGenerationFailed,
                        "Спроба генерації нових ключів з неправильним паролем.", ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString());
                    return RedirectToPage();
                }

                // Тепер генеруємо з паролем
                byte[] newPrivateKeyEncryptionKey = _cryptographyService.DeriveKeyFromPassword(Input.CurrentPasswordForNewKeys, newPkEncryptionSaltBytes);
                var (newEncryptedPrivateKeyBytes, newPkEncryptionIv) = _cryptographyService.EncryptAes(Encoding.UTF8.GetBytes(newPrivateKeyPem), newPrivateKeyEncryptionKey);

                byte[] newIvAndEncryptedPrivateKey = new byte[newPkEncryptionIv.Length + newEncryptedPrivateKeyBytes.Length];
                Buffer.BlockCopy(newPkEncryptionIv, 0, newIvAndEncryptedPrivateKey, 0, newPkEncryptionIv.Length);
                Buffer.BlockCopy(newEncryptedPrivateKeyBytes, 0, newIvAndEncryptedPrivateKey, newPkEncryptionIv.Length, newEncryptedPrivateKeyBytes.Length);

                user.EncryptedPrivateKeyPem = Convert.ToBase64String(newIvAndEncryptedPrivateKey);
                user.PrivateKeyEncryptionSalt = newPrivateKeyEncryptionSaltBase64;
                user.PublicKeyPem = newPublicKeyPem;


                var updateResult = await _userManager.UpdateAsync(user);
                if (updateResult.Succeeded)
                {
                    StatusMessage = "Ваші ключі шифрування було успішно згенеровано/оновлено.";
                    _logger.LogInformation("User {UserId} successfully generated/updated their encryption keys.", user.Id);
                    await _auditService.LogEventAsync(user.Id, user.Email, AuditEventType.UserCryptoKeysGenerated,
                        "Успішно згенеровано нову пару RSA ключів.", ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString());
                }
                else
                {
                    StatusMessage = "Помилка: Не вдалося зберегти нові ключі шифрування. " + string.Join(", ", updateResult.Errors.Select(e => e.Description));
                    _logger.LogError("Failed to update user {UserId} with new encryption keys. Errors: {Errors}", user.Id, string.Join(", ", updateResult.Errors.Select(e => e.Description)));
                    await _auditService.LogEventAsync(user.Id, user.Email, AuditEventType.UserCryptoKeysGenerationFailed,
                       "Не вдалося зберегти нові ключі: " + string.Join(", ", updateResult.Errors.Select(e => e.Description)), ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString());
                }
            }
            catch (Exception ex)
            {
                StatusMessage = "Помилка: Виникла помилка при генерації нових ключів. " + ex.Message;
                _logger.LogError(ex, "Error generating new encryption keys for user {UserId}", user.Id);
                await _auditService.LogEventAsync(user.Id, user.Email, AuditEventType.UserCryptoKeysGenerationFailed,
                    "Виняток при генерації ключів: " + ex.Message, ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString());
            }
            finally
            {
                rsaKeyContainer?.Dispose();
            }
            return RedirectToPage();
        }

        [BindProperty]
        public InputModelForNewKeys Input { get; set; } = new InputModelForNewKeys();

        public class InputModelForNewKeys
        {
            [Required(ErrorMessage = "Поточний пароль є обов'язковим")]
            [DataType(DataType.Password)]
            [Display(Name = "Поточний пароль")]
            public string CurrentPasswordForNewKeys { get; set; }
        }
    }
}
