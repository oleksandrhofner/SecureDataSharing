// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System;
using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using SecureDataSharing.Models;
using Microsoft.Extensions.Logging; // Для ILogger
using SecureDataSharing.Models;      // Для ApplicationUser
using SecureDataSharing.Services;    // Для IAuditService
using SecureDataSharing.Models.Enums; // Для AuditEventType

namespace SecureDataSharing.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<ResetPasswordModel> _logger;
        private readonly IAuditService _auditService;

        public ResetPasswordModel(UserManager<ApplicationUser> userManager,
                                  ILogger<ResetPasswordModel> logger,
                                  IAuditService auditService)
        {
            _userManager = userManager;
            _logger = logger;
            _auditService = auditService;
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
        public class InputModel
        {
            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Required]
            [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [DataType(DataType.Password)]
            [Display(Name = "Confirm password")]
            [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }

            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Required]
            public string Code { get; set; }

        }

        public IActionResult OnGet(string code = null)
        {
            if (code == null)
            {
                return BadRequest("A code must be supplied for password reset.");
            }
            else
            {
                Input = new InputModel
                {
                    // Декодуємо код з Base64Url, оскільки він так генерується
                    Code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code))
                };
                return Page();
            }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
            {
                // Не розкриваємо, що користувача не існує
                _logger.LogWarning("Password reset attempt for non-existent email: {Email}", Input.Email);
                return RedirectToPage("./ResetPasswordConfirmation");
            }

            var result = await _userManager.ResetPasswordAsync(user, Input.Code, Input.Password);
            if (result.Succeeded)
            {
                _logger.LogInformation("User {Email} successfully reset their password.", user.Email);
                await _auditService.LogEventAsync(user.Id, user.Email, AuditEventType.UserPasswordResetSuccess,
                    "Пароль для входу успішно скинуто.");

                // --- ОЧИЩЕННЯ КРИПТОГРАФІЧНИХ КЛЮЧІВ ---
                _logger.LogInformation("Attempting to clear cryptographic keys for user {Email} after password reset.", user.Email);
                user.PublicKeyPem = null;
                user.EncryptedPrivateKeyPem = null;
                user.PrivateKeyEncryptionSalt = null;

                var updateResult = await _userManager.UpdateAsync(user);
                if (updateResult.Succeeded)
                {
                    _logger.LogInformation("Successfully cleared cryptographic keys for user {Email} after password reset.", user.Email);
                    await _auditService.LogEventAsync(user.Id, user.Email, AuditEventType.UserCryptoKeysClearedAfterReset,
                        "Криптографічні ключі користувача було очищено після скидання пароля.");
                    // Встановлюємо повідомлення для сторінки підтвердження
                    TempData["PasswordResetConsequence"] = "Ваш пароль для входу було успішно змінено. " +
                        "Однак, через скидання пароля, доступ до всіх раніше зашифрованих вами даних та файлів втрачено. " +
                        "Ваші попередні ключі шифрування було видалено для забезпечення безпеки.";
                }
                else
                {
                    _logger.LogError("Failed to clear cryptographic keys for user {Email} after password reset. Errors: {Errors}",
                        user.Email, string.Join(", ", updateResult.Errors.Select(e => e.Description)));
                    await _auditService.LogEventAsync(user.Id, user.Email, AuditEventType.UserCryptoKeysClearanceFailed,
                        "Не вдалося очистити криптографічні ключі після скидання пароля: " + string.Join(", ", updateResult.Errors.Select(e => e.Description)));
                    TempData["PasswordResetConsequence"] = "Ваш пароль для входу було успішно змінено. " +
                        "Однак, виникла помилка при очищенні ваших попередніх ключів шифрування. Будь ласка, зверніться до підтримки.";
                }
                // --- КІНЕЦЬ ОЧИЩЕННЯ КЛЮЧІВ ---

                return RedirectToPage("./ResetPasswordConfirmation");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return Page();
        }
    }
}
