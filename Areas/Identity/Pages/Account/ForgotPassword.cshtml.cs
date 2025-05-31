// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System;
using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using SecureDataSharing.Models;

namespace SecureDataSharing.Areas.Identity.Pages.Account
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailSender<ApplicationUser> _emailSender; // <--- Перевірте тип тут
        private readonly ILogger<ForgotPasswordModel> _logger;

        public ForgotPasswordModel(UserManager<ApplicationUser> userManager, IEmailSender<ApplicationUser> emailSender, ILogger<ForgotPasswordModel> logger) // <--- І тут
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _logger = logger; // Якщо є
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
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(Input.Email);
                // Прибираємо перевірку IsEmailConfirmedAsync для функції скидання пароля.
                if (user == null)
                {
                    // Don't reveal that the user does not exist
                    _logger?.LogInformation("Password reset requested for non-existent email: {Email}", Input.Email);
                    return RedirectToPage("./ForgotPasswordConfirmation");
                }

                // Якщо користувач існує, генеруємо токен і посилання
                _logger?.LogInformation("Password reset token requested for user: {Email}", Input.Email);
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                var callbackUrl = Url.Page(
                    "/Account/ResetPassword", // Сторінка, на яку веде посилання
                    pageHandler: null,
                    values: new { area = "Identity", code },
                    protocol: Request.Scheme);

                _logger?.LogInformation("Generated password reset callback URL for {Email}: {CallbackUrl}", Input.Email, callbackUrl);

                // Викликаємо правильний метод з IEmailSender<ApplicationUser>
                await _emailSender.SendPasswordResetLinkAsync(
                    user,       // Передаємо об'єкт користувача
                    Input.Email,
                    callbackUrl // Передаємо готове посилання
                );

                _logger?.LogInformation("Password reset link processed for {Email}. Redirecting to confirmation.", Input.Email);
                return RedirectToPage("./ForgotPasswordConfirmation");
            }

            return Page();
        }
    }
}
