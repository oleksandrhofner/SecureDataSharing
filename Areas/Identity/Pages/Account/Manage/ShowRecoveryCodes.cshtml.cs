// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using SecureDataSharing.Models;

namespace SecureDataSharing.Areas.Identity.Pages.Account.Manage
{
    /// <summary>
    ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
    ///     directly from your code. This API may change or be removed in future releases.
    /// </summary>
    public class ShowRecoveryCodesModel : PageModel
    {
        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        [TempData]
        public string[] RecoveryCodes { get; set; }

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
        public IActionResult OnGet()
        {
            if (RecoveryCodes == null || RecoveryCodes.Length == 0)
            {
                return RedirectToPage("./TwoFactorAuthentication");
            }

            return Page();
        }

        public IActionResult OnPostDownload([FromForm] string[] codesForDownload)
        {
            if (codesForDownload == null || !codesForDownload.Any())
            {
                StatusMessage = "Помилка: Коди відновлення для завантаження не знайдено.";
                return RedirectToPage("./GenerateRecoveryCodes");
            }

            // Для отримання імені користувача потрібен UserManager

            var userNameForFile = User.Identity?.Name?.Replace("@", "_").Replace(".", "_") ?? "recovery-codes";
            if (string.IsNullOrWhiteSpace(User.Identity?.Name)) userNameForFile = "recovery-codes";

            var fileName = $"SecureDataSharing_RecoveryCodes_{userNameForFile}.txt";

            var fileContentBuilder = new System.Text.StringBuilder();
            fileContentBuilder.AppendLine("==================================================");
            fileContentBuilder.AppendLine("  Коди Відновлення для Двофакторної Автентифікації SecureDataSharing  ");
            fileContentBuilder.AppendLine("==================================================");

            fileContentBuilder.AppendLine($"Дата генерації: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            fileContentBuilder.AppendLine();
            fileContentBuilder.AppendLine("- Зберігайте ці коди в дуже надійному та безпечному місці.");
            fileContentBuilder.AppendLine("- Якщо ви втратите доступ до свого пристрою автентифікації, ці коди будуть єдиним способом відновити доступ до вашого облікового запису.");
            fileContentBuilder.AppendLine("- Кожен код можна використати лише один раз.");
            fileContentBuilder.AppendLine("==================================================");
            fileContentBuilder.AppendLine();

            foreach (var code in codesForDownload)
            {
                fileContentBuilder.AppendLine(code);
            }

            fileContentBuilder.AppendLine();
            fileContentBuilder.AppendLine("==================================================");

            byte[] fileBytes = System.Text.Encoding.UTF8.GetBytes(fileContentBuilder.ToString());

            return File(fileBytes, "text/plain", fileName);
        }
    }
}
