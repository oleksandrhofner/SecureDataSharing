// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using SecureDataSharing.Models;// Для ApplicationUser
using SecureDataSharing.Services;
using System.Text;
using System.Security.Cryptography; // Для Encoding

namespace SecureDataSharing.Areas.Identity.Pages.Account
{
    public class RegisterModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IUserStore<ApplicationUser> _userStore;
        private readonly IUserEmailStore<ApplicationUser> _emailStore;
        private readonly ILogger<RegisterModel> _logger;
        private readonly IEmailSender _emailSender;
        private readonly ICryptographyService _cryptographyService;

        public RegisterModel(
            UserManager<ApplicationUser> userManager,
            IUserStore<ApplicationUser> userStore,
            SignInManager<ApplicationUser> signInManager,
            ILogger<RegisterModel> logger,
            IEmailSender emailSender,
            ICryptographyService cryptographyService)
        {
            _userManager = userManager;
            _userStore = userStore;
            _emailStore = GetEmailStore();
            _signInManager = signInManager;
            _logger = logger;
            _emailSender = emailSender;
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
        public string ReturnUrl { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public IList<AuthenticationScheme> ExternalLogins { get; set; }

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
            [Display(Name = "Email")]
            public string Email { get; set; }

            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Required]
            [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
            [DataType(DataType.Password)]
            [Display(Name = "Password")]
            public string Password { get; set; }

            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [DataType(DataType.Password)]
            [Display(Name = "Confirm password")]
            [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }
        }


        public async Task OnGetAsync(string returnUrl = null)
        {
            ReturnUrl = returnUrl;
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
        }

        public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");

            if (ModelState.IsValid)
            {
                var user = CreateUser();

                await _userStore.SetUserNameAsync(user, Input.Email, CancellationToken.None);
                await _emailStore.SetEmailAsync(user, Input.Email, CancellationToken.None);

                // --- Початок генерації та збереження ключів ---
                try
                {
                    // 1. Генеруємо RSA пару ключів
                    var (publicKeyRsa, privateKeyRsa) = _cryptographyService.GenerateRsaKeyPair(); // Використовуємо один RSA об'єкт

                    user.PublicKeyPem = _cryptographyService.ExportPublicKeyToPem(publicKeyRsa);
                    string privateKeyPem = _cryptographyService.ExportPrivateKeyToPem(privateKeyRsa); // Отримуємо приватний ключ у PEM

                    // 2. Генеруємо сіль для шифрування приватного ключа
                    byte[] pkEncryptionSaltBytes = _cryptographyService.GenerateSalt();
                    user.PrivateKeyEncryptionSalt = Convert.ToBase64String(pkEncryptionSaltBytes);



                    // 3. Генеруємо ключ для шифрування приватного ключа з пароля користувача
                    byte[] privateKeyEncryptionKey = _cryptographyService.DeriveKeyFromPassword(Input.Password, pkEncryptionSaltBytes);
                    _logger.LogInformation("REG_ENCRYPT: Key for PK encryption (Base64): {KeyBase64}", Convert.ToBase64String(privateKeyEncryptionKey));

                    // 4. Шифруємо PEM-рядок приватного ключа
                    byte[] privateKeyPemBytes = Encoding.UTF8.GetBytes(privateKeyPem);
                    var (encryptedPrivateKeyBytes, pkEncryptionIv) = _cryptographyService.EncryptAes(privateKeyPemBytes, privateKeyEncryptionKey);

                    // Зберігаємо зашифрований приватний ключ та IV. IV можна додати до шифротексту або зберігати окремо.
                    // модифікуємо EncryptedPrivateKeyPem для зберігання IV + шифротексту
                    byte[] ivAndEncryptedPrivateKey = new byte[pkEncryptionIv.Length + encryptedPrivateKeyBytes.Length];
                    Buffer.BlockCopy(pkEncryptionIv, 0, ivAndEncryptedPrivateKey, 0, pkEncryptionIv.Length);
                    Buffer.BlockCopy(encryptedPrivateKeyBytes, 0, ivAndEncryptedPrivateKey, pkEncryptionIv.Length, encryptedPrivateKeyBytes.Length);
                    user.EncryptedPrivateKeyPem = Convert.ToBase64String(ivAndEncryptedPrivateKey);
                    _logger.LogInformation("RSA key pair generated and private key encrypted for user {UserEmail}.", Input.Email);
                    _logger.LogInformation("REG_TEST: Attempting to decrypt private key immediately after encryption for user {UserEmail}.", Input.Email);
                    _logger.LogInformation("REG_TEST: Salt used for encryption (Base64): {Salt}", user.PrivateKeyEncryptionSalt);

                    _logger.LogInformation("REG_TEST: Encrypted PK to be stored (Base64 prefix): {PK}", user.EncryptedPrivateKeyPem?.Substring(0, Math.Min(30, user.EncryptedPrivateKeyPem?.Length ?? 0)));
                    try
                    {

                        if (user.EncryptedPrivateKeyPem != null && user.PrivateKeyEncryptionSalt != null)
                        {
                            RSA testDecryptedKey = _cryptographyService.GetDecryptedPrivateKey(user.EncryptedPrivateKeyPem, user.PrivateKeyEncryptionSalt, Input.Password);
                            if (testDecryptedKey != null)
                            {
                                _logger.LogInformation("REG_TEST: SUCCESS - Private key decrypted for {UserEmail} using Input.Password and generated salt.", Input.Email);
                                testDecryptedKey.Dispose(); // Важливо звільнити ресурси RSA ключа
                            }
                            else
                            {

                                _logger.LogError("REG_TEST: FAILED - GetDecryptedPrivateKey returned null for {UserEmail} (this should not happen, an exception was expected).", Input.Email);
                            }
                        }
                        else
                        {
                            _logger.LogError("REG_TEST: FAILED - EncryptedPrivateKeyPem or PrivateKeyEncryptionSalt is null for user {UserEmail} before test decryption.", Input.Email);
                        }
                    }
                    catch (Exception ex_reg_test)
                    {
                        _logger.LogError(ex_reg_test, "REG_TEST: FAILED - Exception during immediate test decryption for {UserEmail}.", Input.Email);
                    }

                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Помилка при генерації або шифруванні ключів для користувача {UserEmail}", Input.Email);
                    ModelState.AddModelError(string.Empty, "Не вдалося створити криптографічні ключі. Спробуйте пізніше.");
                    return Page();
                }
                // --- Кінець генерації та збереження ключів ---


                var result = await _userManager.CreateAsync(user, Input.Password);

                if (result.Succeeded)
                {
                    _logger.LogInformation("User created a new account with password.");



                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return LocalRedirect(returnUrl);
                }
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            // If we got this far, something failed, redisplay form
            return Page();
        }

        private ApplicationUser CreateUser()
        {
            try
            {
                // створюється екземпляр ApplicationUser
                return Activator.CreateInstance<ApplicationUser>();
            }
            catch
            {
                throw new InvalidOperationException($"Can't create an instance of '{nameof(ApplicationUser)}'. " +
                    $"Ensure that '{nameof(ApplicationUser)}' is not an abstract class and has a parameterless constructor, or alternatively " +
                    $"override the register page in /Areas/Identity/Pages/Account/Register.cshtml");
            }
        }


        private IUserEmailStore<ApplicationUser> GetEmailStore()
        {
            if (!_userManager.SupportsUserEmail)
            {
                throw new NotSupportedException("The default UI requires a user store with email support.");
            }
            return (IUserEmailStore<ApplicationUser>)_userStore;
        }
    }
}
