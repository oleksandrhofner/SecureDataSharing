// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using SecureDataSharing.Models;
using SecureDataSharing.Models.Enums;
using SecureDataSharing.Services;
using SecureDataSharing.Data; //простір імен для доступу до _context


namespace SecureDataSharing.Areas.Identity.Pages.Account.Manage
{
    public class DeletePersonalDataModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<DeletePersonalDataModel> _logger;
        private readonly ApplicationDbContext _context;
        private readonly IAuditService _auditService;

        public DeletePersonalDataModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ILogger<DeletePersonalDataModel> logger,
            ApplicationDbContext context,
            IAuditService auditService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _context = context;
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
            [DataType(DataType.Password)]
            public string Password { get; set; }
        }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public bool RequirePassword { get; set; }

        public async Task<IActionResult> OnGet()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            RequirePassword = await _userManager.HasPasswordAsync(user);
            return Page();
        }

        public async Task<IActionResult> OnPostAsync() 
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            // Перевірка пароля 
            if (!await _userManager.CheckPasswordAsync(user, Input.Password)) 
            {
                ModelState.AddModelError(string.Empty, "Incorrect password.");
                return Page();
            }

            _logger.LogInformation("User {UserId} initiated account deletion with correct password.", user.Id);

            // --- Спочатку видаляємо залежні дані, які не видаляться каскадом від AuditLog ---
            try
            {
                var permissionsReceived = await _context.DataPermissions
                                                .Where(p => p.RecipientUserId == user.Id)
                                                .ToListAsync();
                if (permissionsReceived.Any())
                {
                    _context.DataPermissions.RemoveRange(permissionsReceived);
                    _logger.LogInformation("Deleting {Count} permissions received by user {UserId} before account deletion.", permissionsReceived.Count, user.Id);
                    
                }
                
                if (permissionsReceived.Any())
                {
                    await _context.SaveChangesAsync();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during manual deletion of dependent data for user {UserId} before account deletion.", user.Id);
                ModelState.AddModelError(string.Empty, "Помилка при видаленні пов'язаних даних. Акаунт не видалено.");
                await _auditService.LogEventAsync(user.Id, user.Email, AuditEventType.UserAccountDeletionFailed,
                    "Помилка при видаленні пов'язаних даних перед видаленням акаунта: " + ex.Message,
                    "ApplicationUser", user.Id, HttpContext.Connection.RemoteIpAddress?.ToString());
                return Page();
            }
            // --- Кінець видалення залежних даних ---

            string userIdForLog = user.Id;
            string userEmailForLog = user.Email!;

            // --- ЛОГУЄМО ПОДІЮ ВИДАЛЕННЯ АКАУНТА ДО ФАКТИЧНОГО ВИДАЛЕННЯ КОРИСТУВАЧА З БД ---
            await _auditService.LogEventAsync(userIdForLog, userEmailForLog, AuditEventType.UserAccountDeleted,
                "Ініційовано видалення акаунта користувача.",
                "ApplicationUser", userIdForLog, HttpContext.Connection.RemoteIpAddress?.ToString());


            var result = await _userManager.DeleteAsync(user);

            if (!result.Succeeded)
            {
                _logger.LogError("User {UserId} account deletion failed. Errors: {Errors}", userIdForLog, string.Join(", ", result.Errors.Select(e => e.Description)));
                await _auditService.LogEventAsync(userIdForLog, userEmailForLog, AuditEventType.UserAccountDeletionFailed,
                    "Не вдалося видалити акаунт: " + string.Join(", ", result.Errors.Select(e => e.Description)),
                    "ApplicationUser", userIdForLog, HttpContext.Connection.RemoteIpAddress?.ToString());

                ModelState.AddModelError(string.Empty, $"Не вдалося видалити користувача: {string.Join(", ", result.Errors.Select(e => e.Description))}");
                return Page(); // Повертаємо на сторінку з помилкою
            }

            _logger.LogInformation("User with ID '{UserId}' deleted themselves successfully.", userIdForLog);

            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out after account deletion.");

            TempData["StatusMessage"] = "Ваш акаунт було успішно видалено.";
            return Redirect("~/"); // Редирект на головну сторінку
        }
    }
}
