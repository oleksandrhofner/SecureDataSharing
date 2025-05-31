// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecureDataSharing.Models;
using SecureDataSharing.Services; // Для ICryptographyService
using System.Text;                // Для Encoding
using System.Security.Cryptography; // Для CryptographicException

namespace SecureDataSharing.Areas.Identity.Pages.Account.Manage
{
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<ChangePasswordModel> _logger;
        private readonly ICryptographyService _cryptographyService;

        public ChangePasswordModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ILogger<ChangePasswordModel> logger,
            ICryptographyService cryptographyService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _cryptographyService = cryptographyService;
        }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        [BindProperty]
        public InputModel Input { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        [TempData]
        public string StatusMessage { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public class InputModel
        {
            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "Current password")]
            public string OldPassword { get; set; }

            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Required]
            [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
            [DataType(DataType.Password)]
            [Display(Name = "New password")]
            public string NewPassword { get; set; }

            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [DataType(DataType.Password)]
            [Display(Name = "Confirm new password")]
            [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var hasPassword = await _userManager.HasPasswordAsync(user);
            if (!hasPassword)
            {
                return RedirectToPage("./SetPassword");
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            // Спочатку змінюємо основний пароль користувача через Identity
            var changePasswordResult = await _userManager.ChangePasswordAsync(user, Input.OldPassword, Input.NewPassword);
            if (!changePasswordResult.Succeeded)
            {
                foreach (var error in changePasswordResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return Page();
            }

            // --- ПОЧАТОК ЛОГІКИ ПЕРЕШИФРУВАННЯ ПРИВАТНОГО КЛЮЧА ---
            _logger.LogInformation("User {UserId} changed their password successfully. Attempting to re-encrypt private key.", user.Id);

            if (string.IsNullOrEmpty(user.EncryptedPrivateKeyPem) || string.IsNullOrEmpty(user.PrivateKeyEncryptionSalt))
            {
                _logger.LogWarning("User {UserId} has no encrypted private key or salt. Skipping private key re-encryption.", user.Id);
                // Якщо ключів немає, можливо, це новий користувач
            }
            else
            {
                RSA? plainRsaPrivateKey = null;
                try
                {
                    // 1. Розшифрувати приватний ключ СТАРИМ паролем
                    _logger.LogDebug("Re-encrypt PK: Decrypting private key with OLD password for user {UserId}.", user.Id);
                    plainRsaPrivateKey = _cryptographyService.GetDecryptedPrivateKey(
                        user.EncryptedPrivateKeyPem,
                        user.PrivateKeyEncryptionSalt,
                        Input.OldPassword // ВИКОРИСТОВУЄМО СТАРИЙ ПАРОЛЬ
                    );
                    string privateKeyPem = _cryptographyService.ExportPrivateKeyToPem(plainRsaPrivateKey);
                    byte[] privateKeyPemBytes = Encoding.UTF8.GetBytes(privateKeyPem);

                    // 2. Згенерувати новий ключ шифрування для приватного ключа, використовуючи НОВИЙ пароль та ТУ САМУ сіль
                    _logger.LogDebug("Re-encrypt PK: Deriving new encryption key with NEW password for user {UserId}.", user.Id);
                    byte[] newPrivateKeyEncryptionKey = _cryptographyService.DeriveKeyFromPassword(
                        Input.NewPassword, // ВИКОРИСТОВУЄМО НОВИЙ ПАРОЛЬ
                        Convert.FromBase64String(user.PrivateKeyEncryptionSalt) // Використовуємо існуючу сіль
                    );

                    // 3. Зашифрувати PEM-рядок приватного ключа новим ключем шифрування (і новим IV)
                    _logger.LogDebug("Re-encrypt PK: Encrypting private key PEM with new derived key for user {UserId}.", user.Id);
                    var (newEncryptedPrivateKeyBytes, newPkEncryptionIv) = _cryptographyService.EncryptAes(privateKeyPemBytes, newPrivateKeyEncryptionKey);

                    // 4. Оновити EncryptedPrivateKeyPem користувача
                    byte[] newIvAndEncryptedPrivateKey = new byte[newPkEncryptionIv.Length + newEncryptedPrivateKeyBytes.Length];
                    Buffer.BlockCopy(newPkEncryptionIv, 0, newIvAndEncryptedPrivateKey, 0, newPkEncryptionIv.Length);
                    Buffer.BlockCopy(newEncryptedPrivateKeyBytes, 0, newIvAndEncryptedPrivateKey, newPkEncryptionIv.Length, newEncryptedPrivateKeyBytes.Length);

                    user.EncryptedPrivateKeyPem = Convert.ToBase64String(newIvAndEncryptedPrivateKey);

                    // 5. Зберегти оновлені дані користувача
                    var updateResult = await _userManager.UpdateAsync(user);
                    if (updateResult.Succeeded)
                    {
                        _logger.LogInformation("User {UserId}'s private key was successfully re-encrypted with the new password.", user.Id);
                    }
                    else
                    {
                        _logger.LogError("Failed to update user {UserId} after re-encrypting private key. Errors: {Errors}", user.Id, string.Join(", ", updateResult.Errors.Select(e => e.Description)));
                        ModelState.AddModelError(string.Empty, "Пароль було змінено, але виникла помилка при оновленні захисту ваших даних. Будь ласка, зверніться до підтримки.");
                        
                    }
                }
                catch (CryptographicException cex)
                {
                    _logger.LogError(cex, "Re-encrypt PK: Cryptographic error while re-encrypting private key for user {UserId}. THIS IS CRITICAL as password was changed but PK re-encryption failed.", user.Id);
                    ModelState.AddModelError(string.Empty, "Пароль було змінено, але виникла серйозна криптографічна помилка при оновленні захисту ваших даних. Старий пароль міг бути невірним для розшифрування ключів, або сталася інша помилка. Зверніться до підтримки!");
                    
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Re-encrypt PK: Generic error while re-encrypting private key for user {UserId}. THIS IS CRITICAL.", user.Id);
                    ModelState.AddModelError(string.Empty, "Пароль було змінено, але виникла неочікувана помилка при оновленні захисту ваших даних. Зверніться до підтримки!");
                    
                }
                finally
                {
                    plainRsaPrivateKey?.Dispose();
                }
            }
            // --- КІНЕЦЬ ЛОГІКИ ПЕРЕШИФРУВАННЯ ---

            await _signInManager.RefreshSignInAsync(user);
            _logger.LogInformation("User changed their password successfully and sign-in state refreshed for {UserId}.", user.Id);
            StatusMessage = "Your password has been changed.";

            return Page();
        }
    }
}
