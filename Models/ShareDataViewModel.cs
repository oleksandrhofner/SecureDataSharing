using Microsoft.AspNetCore.Mvc.Rendering;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace SecureDataSharing.Models
{
    public class ShareDataViewModel
    {
        public int StoredDataId { get; set; }
        public string? DataName { get; set; }

        [Required(ErrorMessage = "Будь ласка, виберіть користувача.")]
        [Display(Name = "Надати доступ користувачеві")]
        public string? SelectedRecipientUserId { get; set; }

        public List<SelectListItem>? PotentialRecipients { get; set; }
        public List<ExistingPermissionViewModel>? ExistingPermissions { get; set; }

        // Пароль власника для підтвердження операції
        [Required(ErrorMessage = "Будь ласка, введіть ваш поточний пароль для підтвердження.")]
        [DataType(DataType.Password)]
        [Display(Name = "Ваш пароль (для підтвердження)")]
        public string? OwnerPassword { get; set; }
    }
}