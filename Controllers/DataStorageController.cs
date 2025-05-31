using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization; // Для атрибуту [Authorize]
using SecureDataSharing.Models; // Або де знаходиться CreateDataViewModel
using SecureDataSharing.Data; // Для DbContext
using Microsoft.AspNetCore.Identity; // Для UserManager
using System.Threading.Tasks;
using System.Security.Claims; // Для User.FindFirstValue
using System.Security.Cryptography; // Для AES
using System.Text; // Для Encoding
using Microsoft.EntityFrameworkCore; // Може знадобитися для Include
// Додаємо цей using для MemoryStream, CryptoStream, StreamReader
using System.IO;
using Microsoft.AspNetCore.Mvc.Rendering;
using SecureDataSharing.Services; // Для ICryptographyService
using Microsoft.Extensions.Logging; // Для ILogger
using Microsoft.AspNetCore.Http; // Для IFormFile
using System.Linq;
using System.Collections.Generic;
using SecureDataSharing.Helpers;
using SecureDataSharing.Models.Enums;


namespace SecureDataSharing.Controllers
{
    [Authorize] // Тільки авторизовані користувачі можуть додавати дані
    public class DataStorageController : Controller
    {

        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ICryptographyService _cryptographyService;
        private readonly ILogger<DataStorageController> _logger;
        private readonly IAuditService _auditService;

        // Конструктор для отримання сервісів
        public DataStorageController(
            ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            ICryptographyService cryptographyService,
            ILogger<DataStorageController> logger,
            IAuditService auditService)
        {
            _context = context;
            _userManager = userManager;
            _cryptographyService = cryptographyService;
            _logger = logger;
            _auditService = auditService;
        }
        // GET: DataStorage/Create
        public IActionResult Create()
        {
            ViewBag.MaxFileSize = MaxFileSize;
            return View();
        }


        private const long MaxFileSize = 2L * 1024 * 1024 * 1024; // 2 GB в байтах
        // POST: DataStorage/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(CreateDataViewModel model)
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var currentUser = await _userManager.FindByIdAsync(currentUserId);

            if (currentUser == null || string.IsNullOrEmpty(currentUser.PublicKeyPem))
            {
                ModelState.AddModelError(string.Empty, "Не вдалося знайти користувача або його публічний ключ.");
            }

            if (!string.IsNullOrEmpty(model.UserPassword)) // Перевіряємо пароль, якщо він наданий
            {
                var passwordCheck = await _userManager.CheckPasswordAsync(currentUser!, model.UserPassword);
                if (!passwordCheck)
                {
                    ModelState.AddModelError("UserPassword", "Неправильний пароль.");
                }
            }
            else // Пароль обов'язковий
            {
                ModelState.AddModelError("UserPassword", "Пароль є обов'язковим.");
            }


            if (model.DataType == StorageEntryType.Text && string.IsNullOrWhiteSpace(model.PlainTextData))
            {
                ModelState.AddModelError("PlainTextData", "Для текстового запису дані не можуть бути порожніми.");
            }
            else if (model.DataType == StorageEntryType.File)
            {
                if (model.FileToUpload == null || model.FileToUpload.Length == 0)
                {
                    ModelState.AddModelError("FileToUpload", "Для файлового запису потрібно вибрати файл.");
                }
                else if (model.FileToUpload.Length > MaxFileSize) // Перевірка розміру
                {
                    ModelState.AddModelError("FileToUpload", $"Розмір файлу не повинен перевищувати {MaxFileSize / 1024 / 1024} MB.");
                }
            }
            else if (model.DataType == 0)
            {
                ModelState.AddModelError("DataType", "Будь ласка, виберіть тип запису.");
            }

            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Create POST: ModelState is invalid for user {UserId}. Errors: {Errors}",
                    currentUserId,
                    string.Join("; ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage)));
                return View(model);
            }

            byte[] contentBytesToEncrypt;
            string? originalFileName = null;
            string? contentType = null;
            long? fileSize = null;

            if (model.DataType == StorageEntryType.Text)
            {
                contentBytesToEncrypt = Encoding.UTF8.GetBytes(model.PlainTextData!);
                _logger.LogInformation("Creating TEXT entry: {DataName} for user {UserId}. Text length: {Length}", model.DataName, currentUserId, contentBytesToEncrypt.Length);
            }
            else
            {
                originalFileName = model.FileToUpload!.FileName;
                contentType = model.FileToUpload.ContentType;
                fileSize = model.FileToUpload.Length;

                _logger.LogInformation("Creating FILE entry: {OriginalFileName} (ContentType: {ContentType}, Size: {FileSize}) for StoredData name: {DataName}, user {UserId}.",
                    originalFileName, contentType, fileSize, model.DataName, currentUserId);

                // Читаємо файл у масив байтів.
                // Для дуже великих файлів це може бути неефективно
                using (var memoryStream = new MemoryStream())
                {
                    await model.FileToUpload.CopyToAsync(memoryStream);
                    contentBytesToEncrypt = memoryStream.ToArray();
                }
                _logger.LogDebug("File {OriginalFileName} read into memory. Byte length: {Length}", originalFileName, contentBytesToEncrypt.Length);
            }

            try
            {
                // 1. Генеруємо новий DEK (симетричний ключ, наприклад, AES 256)
                byte[] dek = _cryptographyService.GenerateSalt(32); // Використовуємо GenerateSalt для отримання випадкових байтів
                _logger.LogDebug("Generated DEK for {DataName}. DEK length: {Length}", model.DataName, dek.Length);

                // 2. Шифруємо вміст (текст або файл) за допомогою DEK
                var (encryptedContent, dataIv) = _cryptographyService.EncryptAes(contentBytesToEncrypt, dek);
                _logger.LogDebug("Content encrypted for {DataName}. Encrypted length: {Length}, IV (Base64): {IV}", model.DataName, encryptedContent.Length, Convert.ToBase64String(dataIv));


                // 3. Шифруємо DEK публічним ключем власника
                RSA ownerPublicKey = _cryptographyService.ImportPublicKeyFromPem(currentUser.PublicKeyPem!);
                byte[] encryptedDekForOwner = _cryptographyService.EncryptRsa(dek, ownerPublicKey);
                ownerPublicKey.Dispose(); // Звільняємо ресурси RSA ключа
                _logger.LogDebug("DEK for {DataName} encrypted with owner's public key. Encrypted DEK length: {Length}", model.DataName, encryptedDekForOwner.Length);


                var storedData = new StoredData
                {
                    OwnerUserId = currentUserId,
                    DataName = model.DataName,
                    DataType = model.DataType,
                    EncryptedContentBytes = encryptedContent, // Зашифрований вміст (текст або файл)
                    InitializationVector = dataIv,
                    EncryptedDekForOwner = encryptedDekForOwner,
                    OriginalFileName = originalFileName,
                    ContentType = contentType,
                    FileSize = fileSize,
                    Timestamp = DateTime.UtcNow
                };

                _context.Add(storedData);
                await _context.SaveChangesAsync();

                TempData["SuccessMessage"] = $"Запис '{storedData.DataName}' ({storedData.DataType}) успішно збережено та зашифровано.";
                _logger.LogInformation("StoredData entry {DataId} ('{DataName}', type {DataType}) created successfully for user {UserId}.", storedData.Id, storedData.DataName, storedData.DataType, currentUserId);
                // --- ЛОГУВАННЯ АУДИТУ ---
                await _auditService.LogEventAsync(
                    currentUserId,
                    currentUser?.Email,
                    AuditEventType.DataCreated,
                    $"Створено запис: '{storedData.DataName}'. Тип: {storedData.DataType}. " +
                    (storedData.DataType == StorageEntryType.File ? $"Файл: {storedData.OriginalFileName}, Розмір: {storedData.FileSize} байт." : "Текстовий запис."),
                    "StoredData",
                    storedData.Id.ToString()
                );

                return RedirectToAction(nameof(Index));
            }
            catch (CryptographicException ex)
            {
                _logger.LogError(ex, "Create POST: Cryptographic error during encryption for user {UserId}, DataName: {DataName}", currentUserId, model.DataName);
                ModelState.AddModelError(string.Empty, "Виникла криптографічна помилка при збереженні даних.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Create POST: General error for user {UserId}, DataName: {DataName}", currentUserId, model.DataName);
                ModelState.AddModelError(string.Empty, "Виникла неочікувана помилка при збереженні даних.");
            }

            // Якщо виникла помилка, повертаємо View з моделлю
            return View(model);
        }

        // GET: DataStorage/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null) return NotFound("ID is null.");

            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var currentUser = await _userManager.FindByIdAsync(currentUserId);
            if (currentUser == null) return Unauthorized();

            var storedData = await _context.StoredDatas
                                     .Include(sd => sd.OwnerUser)
                                     .FirstOrDefaultAsync(d => d.Id == id);

            if (storedData == null) return NotFound("Запис даних не знайдено.");

            bool isOwner = storedData.OwnerUserId == currentUserId;
            bool hasSharedPermission = false;
            if (!isOwner)
            {
                hasSharedPermission = await _context.DataPermissions
                                            .AnyAsync(p => p.StoredDataId == id && p.RecipientUserId == currentUserId);
            }

            if (!isOwner && !hasSharedPermission)
            {
                return Forbid("У вас немає дозволу на перегляд цих даних.");
            }

            var viewModel = new DetailsViewModel
            {
                Id = storedData.Id,
                DataName = storedData.DataName,
                Timestamp = storedData.Timestamp,
                DataType = storedData.DataType,
                OriginalFileName = storedData.OriginalFileName,
                ContentType = storedData.ContentType,
                FileSize = storedData.FileSize,
                DecryptedText = "[Дані зашифровано. Введіть пароль для доступу.]",
                UserHasPermission = true,
                RequirePasswordPrompt = true
            };

            ViewBag.DataId = id; // Для форми запиту пароля
            return View(viewModel);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ViewDecrypted(int id, [FromForm] string userPassword)
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var currentUser = await _userManager.FindByIdAsync(currentUserId!);

            if (currentUser == null || string.IsNullOrEmpty(currentUser.EncryptedPrivateKeyPem) || string.IsNullOrEmpty(currentUser.PrivateKeyEncryptionSalt))
            {
                _logger.LogWarning("ViewDecrypted POST: User {UserId} data is incomplete for decryption for StoredData ID {DataId}.", currentUserId, id);
                TempData["ErrorMessage"] = "Дані користувача неповні для операції дешифрування.";
                return RedirectToAction(nameof(Details), new { id = id });
            }

            var storedData = await _context.StoredDatas
                                     .Include(sd => sd.OwnerUser)
                                     .FirstOrDefaultAsync(d => d.Id == id);

            if (storedData == null)
            {
                _logger.LogWarning("ViewDecrypted POST: StoredData ID {DataId} not found.", id);
                return NotFound("Запис даних не знайдено.");
            }

            bool isOwner = storedData.OwnerUserId == currentUserId;
            DataPermission? permission = null;
            if (!isOwner)
            {
                permission = await _context.DataPermissions
                                       .FirstOrDefaultAsync(p => p.StoredDataId == id && p.RecipientUserId == currentUserId);
                if (permission == null)
                {
                    _logger.LogWarning("ViewDecrypted POST: User {UserId} does not have permission for StoredData ID {DataId}.", currentUserId, id);
                    return Forbid("У вас немає дозволу на перегляд цих даних.");
                }
            }

            var viewModel = new DetailsViewModel
            {
                Id = storedData.Id,
                DataName = storedData.DataName,
                Timestamp = storedData.Timestamp,
                DataType = storedData.DataType,
                OriginalFileName = storedData.OriginalFileName,
                ContentType = storedData.ContentType,
                FileSize = storedData.FileSize,
                UserHasPermission = true,
                IsOwner = isOwner,
                RequirePasswordPrompt = true
            };
            ViewBag.DataId = id;

            if (string.IsNullOrEmpty(userPassword))
            {
                ModelState.AddModelError("userPassword", "Пароль не може бути порожнім.");
                viewModel.ErrorMessage = "Пароль не може бути порожнім.";
                viewModel.DecryptedText = "[Дані зашифровано. Введіть пароль для доступу.]";
                return View("Details", viewModel);
            }

            var passwordCheck = await _userManager.CheckPasswordAsync(currentUser, userPassword);
            if (!passwordCheck)
            {
                _logger.LogWarning("ViewDecrypted POST: Incorrect password for User {UserId} trying to access StoredData ID {DataId}.", currentUserId, id);
                viewModel.ErrorMessage = "Неправильний пароль.";
                viewModel.DecryptedText = "[Неправильний пароль. Дані не розшифровано]";
                return View("Details", viewModel);
            }

            // Логування спроби доступу ПІСЛЯ перевірки пароля
            await _auditService.LogEventAsync(currentUserId, currentUser.Email, AuditEventType.DataAccessAttempt,
                $"Спроба доступу/дешифрування даних ID: {id} (Пароль коректний).", "StoredData", id.ToString());

            RSA? userPrivateKey = null;
            try
            {
                userPrivateKey = _cryptographyService.GetDecryptedPrivateKey(
                    currentUser.EncryptedPrivateKeyPem,
                    currentUser.PrivateKeyEncryptionSalt,
                    userPassword
                );

                byte[] dek;
                if (isOwner)
                {
                    if (storedData.EncryptedDekForOwner == null) throw new CryptographicException("Ключ DEK для власника відсутній.");
                    dek = _cryptographyService.DecryptRsa(storedData.EncryptedDekForOwner, userPrivateKey);
                }
                else // Отримувач
                {
                    if (permission!.EncryptedDekForRecipient == null) throw new CryptographicException("Ключ DEK для отримувача відсутній.");
                    dek = _cryptographyService.DecryptRsa(permission.EncryptedDekForRecipient, userPrivateKey);
                }

                if (storedData.EncryptedContentBytes == null || storedData.InitializationVector == null)
                    throw new InvalidOperationException("Зашифровані дані або IV відсутні.");

                byte[] decryptedBytes = _cryptographyService.DecryptAes(storedData.EncryptedContentBytes, dek, storedData.InitializationVector);

                await _auditService.LogEventAsync(currentUserId, currentUser.Email, AuditEventType.DataDecryptionSuccess,
                    $"Дані ID: {id} ('{(storedData.DataType == StorageEntryType.File ? storedData.OriginalFileName : storedData.DataName)}') успішно розшифровано.", "StoredData", id.ToString());

                if (storedData.DataType == StorageEntryType.Text)
                {
                    string decryptedText = Encoding.UTF8.GetString(decryptedBytes);
                    viewModel.DecryptedText = decryptedText;
                    viewModel.RequirePasswordPrompt = false;

                    if (isOwner) // Зберігаємо в TempData тільки для власника, якщо він захоче редагувати
                    {
                        TempData["DecryptedTextForEdit"] = decryptedText;
                        TempData["DataIdForEdit"] = storedData.Id;
                    }
                    return View("Details", viewModel);
                }
                else if (storedData.DataType == StorageEntryType.File)
                {
                    return File(decryptedBytes, storedData.ContentType ?? "application/octet-stream", storedData.OriginalFileName ?? $"file_{id}");
                }
                else
                {
                    viewModel.ErrorMessage = "Невідомий тип даних.";
                    viewModel.DecryptedText = "[Помилка: невідомий тип даних]";
                    viewModel.RequirePasswordPrompt = false; // Пароль був правильний, але тип даних незрозумілий
                    return View("Details", viewModel);
                }
            }
            catch (CryptographicException ex)
            {
                _logger.LogError(ex, "ViewDecrypted POST: Cryptographic error for Data ID {DataId}, User {UserId}. Message: {ExMessage}", id, currentUserId, ex.Message);
                viewModel.ErrorMessage = "Помилка дешифрування: " + ex.Message;
                viewModel.DecryptedText = "[Помилка дешифрування даних.]";
                await _auditService.LogEventAsync(currentUserId, currentUser.Email, AuditEventType.DataDecryptionFailure,
                    $"Невдала спроба дешифрування даних ID: {id}. Причина: Криптографічна помилка - {ex.Message.Substring(0, Math.Min(ex.Message.Length, 100))}", "StoredData", id.ToString());
                return View("Details", viewModel); // Повертаємо з формою пароля, бо він міг бути неправильним для ключів
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ViewDecrypted POST: Unexpected error for Data ID {DataId}, User {UserId}.", id, currentUserId);
                viewModel.ErrorMessage = "Виникла неочікувана помилка.";
                viewModel.DecryptedText = "[Виникла системна помилка.]";
                await _auditService.LogEventAsync(currentUserId, currentUser.Email, AuditEventType.DataDecryptionFailure,
                   $"Невдала спроба дешифрування даних ID: {id}. Причина: Загальна помилка сервера - {ex.Message.Substring(0, Math.Min(ex.Message.Length, 100))}", "StoredData", id.ToString());
                return View("Details", viewModel);
            }
            finally
            {
                userPrivateKey?.Dispose();
            }
        }

        // GET: DataStorage/Share/5
        public async Task<IActionResult> Share(int? id)
        {
            if (id == null) return NotFound();

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null) return Unauthorized();

            var storedData = await _context.StoredDatas
                                     .FirstOrDefaultAsync(d => d.Id == id && d.OwnerUserId == userId);

            if (storedData == null)
            {
                return NotFound("Ви не можете надати доступ до цих даних, оскільки не є їх власником, або дані не знайдено.");
            }

            // 2. Отримати список користувачів, яким ВЖЕ надано доступ
            var existingPermissionsDetails = await _context.DataPermissions
                                                .Where(p => p.StoredDataId == id)
                                                .Include(p => p.RecipientUser) // Щоб отримати Email та ID
                                                .Select(p => new ExistingPermissionViewModel
                                                {
                                                    RecipientUserId = p.RecipientUser!.Id,
                                                    RecipientEmail = p.RecipientUser!.Email
                                                })
                                                .ToListAsync();

            // 3. Отримати список потенційних отримувачів
            var existingRecipientIds = existingPermissionsDetails.Select(epd => epd.RecipientUserId).ToList();

            var potentialRecipients = await _userManager.Users
                                            .Where(u => u.Id != userId && !existingRecipientIds.Contains(u.Id)) // Порівнюємо по ID
                                            .OrderBy(u => u.Email)
                                            .Select(u => new SelectListItem
                                            {
                                                Value = u.Id,
                                                Text = u.Email
                                            })
                                            .ToListAsync();

            var viewModel = new ShareDataViewModel
            {
                StoredDataId = storedData.Id,
                DataName = storedData.DataName,
                PotentialRecipients = potentialRecipients,
                ExistingPermissions = existingPermissionsDetails
            };

            return View(viewModel);
        }

        [HttpGet]
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                _logger.LogWarning("Delete GET: ID is null.");
                return NotFound("ID запису не вказано.");
            }

            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            // Завантажуємо тільки необхідні метадані для підтвердження
            var dataToConfirm = await _context.StoredDatas
                                        .Where(m => m.Id == id && m.OwnerUserId == currentUserId) // Перевірка власності
                                        .Select(s => new DeleteDataConfirmationViewModel
                                        {
                                            Id = s.Id,
                                            DataName = s.DataName,
                                            DataType = s.DataType,
                                            OriginalFileName = s.OriginalFileName,
                                            OwnerEmail = s.OwnerUser != null ? s.OwnerUser.Email : "N/A"
                                        })
                                        .FirstOrDefaultAsync();

            if (dataToConfirm == null)
            {
                _logger.LogWarning("Delete GET: Data with ID {DataId} not found for user {UserId} or user is not owner.", id, currentUserId);
                TempData["ErrorMessage"] = "Запис не знайдено або у вас немає прав на його видалення.";
                return RedirectToAction(nameof(Index));
            }

            return View(dataToConfirm);
        }



        // POST: DataStorage/DeleteConfirmed/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (currentUserId == null) return Unauthorized();

            // Спочатку перевіряємо, чи користувач є власником і отримуємо DataName для повідомлення
            var dataInfo = await _context.StoredDatas
                                       .Where(m => m.Id == id && m.OwnerUserId == currentUserId)
                                       .Select(m => new { m.Id, m.DataName }) // Отримуємо тільки Id та DataName
                                       .FirstOrDefaultAsync();

            if (dataInfo == null)
            {
                _logger.LogWarning("Delete POST: Data with ID {DataId} not found for deletion by user {UserId} or user is not owner.", id, currentUserId);
                TempData["ErrorMessage"] = "Помилка: Запис не знайдено або у вас немає прав на його видалення.";
                return RedirectToAction(nameof(Index));
            }

            try
            {
                var storedDataToDeleteStub = new StoredData { Id = dataInfo.Id };

                _context.StoredDatas.Attach(storedDataToDeleteStub); // Повідомляємо EF Core, цей об'єкт існує в БД
                _context.StoredDatas.Remove(storedDataToDeleteStub); // Позначаємо його для видалення

                await _context.SaveChangesAsync(); // Видалення з БД видалення дозволів

                _logger.LogInformation("Data with ID {DataId} ('{DataName}') owned by {UserId} was successfully deleted.", dataInfo.Id, dataInfo.DataName, currentUserId);
                TempData["SuccessMessage"] = $"Запис '{dataInfo.DataName}' було успішно видалено.";

                // --- ЛОГУВАННЯ АУДИТУ ---
                await _auditService.LogEventAsync(
                    currentUserId,
                    (await _userManager.FindByIdAsync(currentUserId))?.Email,
                    AuditEventType.DataDeleted,
                    $"Видалено запис: '{dataInfo.DataName}', ID: {dataInfo.Id}",
                    "StoredData",
                    dataInfo.Id.ToString()
                );
            }
            catch (DbUpdateException ex)
            {
                _logger.LogError(ex, "Error deleting data with ID {DataId} from database.", id);
                TempData["ErrorMessage"] = "Помилка при видаленні запису з бази даних.";
            }

            return RedirectToAction(nameof(Index));
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RevokeAccess(int storedDataId, string recipientUserId)
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (currentUserId == null)
            {
                return Unauthorized();
            }

            if (storedDataId == 0 || string.IsNullOrEmpty(recipientUserId))
            {
                TempData["ErrorMessage"] = "Помилка: Необхідні дані для скасування доступу не були передані.";

                return storedDataId != 0 ? RedirectToAction(nameof(Share), new { id = storedDataId }) : RedirectToAction(nameof(Index));
            }

            // 1. Перевірити, чи поточний користувач є власником даних
            var storedData = await _context.StoredDatas
                                         .AsNoTracking() // Дані не будуть змінюватися, тільки перевірка
                                         .FirstOrDefaultAsync(sd => sd.Id == storedDataId && sd.OwnerUserId == currentUserId);

            if (storedData == null)
            {
                TempData["ErrorMessage"] = "Помилка: Ви не можете скасувати доступ до цих даних, оскільки не є їх власником або дані не знайдено.";
                return RedirectToAction(nameof(Index));
            }

            // 2. Знайти та видалити дозвіл
            var permissionToRemove = await _context.DataPermissions
                                             .FirstOrDefaultAsync(dp => dp.StoredDataId == storedDataId &&
                                                                         dp.OwnerUserId == currentUserId && // Додаткова перевірка, що саме власник видаляє
                                                                         dp.RecipientUserId == recipientUserId);

            if (permissionToRemove != null)
            {
                _context.DataPermissions.Remove(permissionToRemove);
                await _context.SaveChangesAsync();
                var recipientUser = await _userManager.FindByIdAsync(recipientUserId); // Для повідомлення
                TempData["SuccessMessage"] = $"Доступ для користувача {recipientUser?.Email ?? "невідомий"} до даних '{storedData.DataName}' успішно скасовано.";
                // --- ЛОГУВАННЯ АУДИТУ ---
                var recipientUserForLog = await _userManager.FindByIdAsync(recipientUserId);
                var ownerUserForLog = await _userManager.FindByIdAsync(currentUserId);
                await _auditService.LogEventAsync(
                    currentUserId, // Власник, який скасовує доступ
                    ownerUserForLog?.Email,
                    AuditEventType.PermissionRevoked,
                    $"Скасовано доступ до даних ID: {storedDataId} (Назва: '{storedData?.DataName ?? "N/A"}') " +
                    $"для отримувача {recipientUserForLog?.Email ?? recipientUserId} (ID: {recipientUserId}).",
                    "DataPermission",
                    storedDataId.ToString()
                );
            }
            else
            {
                TempData["InfoMessage"] = "Дозвіл не знайдено або вже було скасовано.";
            }

            // Повернутися на сторінку "Поділитися" для цих же даних
            return RedirectToAction(nameof(Share), new { id = storedDataId });
        }


        // GET: DataStorage/Edit/5
        [HttpGet]
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                _logger.LogWarning("Edit GET: ID is null.");
                return NotFound("ID запису не вказано.");
            }

            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            // Завантажуємо дані, щоб перевірити власність та отримати метадані
            var storedData = await _context.StoredDatas
                                     .Where(s => s.Id == id && s.OwnerUserId == currentUserId) // Тільки власник може редагувати
                                     .Select(s => new
                                     {
                                         s.Id,
                                         s.DataName,
                                         s.DataType,
                                         s.OriginalFileName,
                                         s.ContentType
                                     })
                                     .FirstOrDefaultAsync();

            if (storedData == null)
            {
                _logger.LogWarning("Edit GET: StoredData ID {DataId} not found for user {UserId} or user is not owner.", id, currentUserId);
                TempData["ErrorMessage"] = "Запис не знайдено або у вас немає прав на його редагування.";
                return RedirectToAction(nameof(Index));
            }

            var viewModel = new EditDataViewModel
            {
                Id = storedData.Id,
                DataName = storedData.DataName,
                DataType = storedData.DataType,
                OriginalFileName = storedData.OriginalFileName,
                ContentType = storedData.ContentType,
                TextContent = null
            };

            if (storedData.DataType == StorageEntryType.Text)
            {
                // Перевіряємо, чи є розшифрований текст у TempData (з перегляду Details)
                if (TempData["DataIdForEdit"] != null && TempData["DataIdForEdit"] is int tempId && tempId == id && TempData["DecryptedTextForEdit"] != null)
                {
                    viewModel.TextContent = TempData["DecryptedTextForEdit"]!.ToString();
                    _logger.LogInformation("Edit GET: Pre-filled TextContent for DataID {DataId} from TempData.", id);

                    TempData.Keep("DecryptedTextForEdit");
                    TempData.Keep("DataIdForEdit");
                }
                else
                {
                    // Якщо тексту в TempData немає, користувач має пройти через Details або побачить порожнє поле
                    viewModel.TextContent = string.Empty;
                    _logger.LogInformation("Edit GET: TextContent for DataID {DataId} not found in TempData. User should input new text or came directly.", id);
                }
            }

            // UserPasswordForSave буде введено у формі
            ViewBag.DataId = id;
            return View(viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(EditDataViewModel model) // метод для ЗБЕРЕЖЕННЯ ЗМІН
        {
            // 1. Базова валідація моделі (з атрибутів Required, StringLength)
            if (!ModelState.IsValid)
            {
                _logger.LogWarning("Edit POST (Save): ModelState is invalid for StoredData ID {DataId}. Errors: {Errors}",
                    model.Id,
                    string.Join("; ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage)));

                ViewBag.DataId = model.Id;
                return View(model);
            }

            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var currentUser = await _userManager.FindByIdAsync(currentUserId!);

            if (currentUser == null || string.IsNullOrEmpty(currentUser.EncryptedPrivateKeyPem) || string.IsNullOrEmpty(currentUser.PrivateKeyEncryptionSalt))
            {
                TempData["ErrorMessage"] = "Помилка: Не вдалося отримати дані користувача для безпечної операції.";
                _logger.LogWarning("Edit POST (Save): User {UserId} data is incomplete for StoredData ID {DataId}.", currentUserId, model.Id);
                return RedirectToAction(nameof(Index));
            }

            // 2. Перевірка пароля користувача (власника) для збереження
            var passwordCheck = await _userManager.CheckPasswordAsync(currentUser, model.UserPasswordForSave!);
            if (!passwordCheck)
            {
                ModelState.AddModelError("UserPasswordForSave", "Неправильний пароль для збереження змін.");
                _logger.LogWarning("Edit POST (Save): Incorrect save password for User {UserId}, StoredData ID {DataId}.", currentUserId, model.Id);

                ViewBag.DataId = model.Id;
                return View(model); // Повертаємо на форму з помилкою
            }

            // 3. Знаходимо існуючий запис StoredData та перевіряємо власність
            var storedItemToUpdate = await _context.StoredDatas
                                             .FirstOrDefaultAsync(s => s.Id == model.Id && s.OwnerUserId == currentUserId);

            if (storedItemToUpdate == null)
            {
                TempData["ErrorMessage"] = "Запис не знайдено або у вас немає прав на його редагування.";
                _logger.LogWarning("Edit POST (Save): StoredData ID {DataId} not found for user {UserId} or user is not owner.", model.Id, currentUserId);
                return RedirectToAction(nameof(Index));
            }

            RSA? ownerPrivateKey = null;

            try
            {
                // 4. Отримуємо розшифрований приватний ключ власника
                _logger.LogDebug("Edit POST (Save): Getting private key for user {UserId} to edit StoredData ID {DataId}", currentUserId, model.Id);
                ownerPrivateKey = _cryptographyService.GetDecryptedPrivateKey(
                    currentUser.EncryptedPrivateKeyPem,
                    currentUser.PrivateKeyEncryptionSalt,
                    model.UserPasswordForSave! // Пароль для збереження, вже перевірений
                );

                // 5. Розшифровуємо існуючий DEK (Data Encryption Key)
                if (storedItemToUpdate.EncryptedDekForOwner == null)
                {
                    _logger.LogError("Edit POST (Save): EncryptedDekForOwner is null for StoredData ID {DataId}. Cannot proceed with edit.", model.Id);
                    TempData["ErrorMessage"] = "Критична помилка: ключ шифрування для цього запису відсутній.";
                    return RedirectToAction(nameof(Details), new { id = model.Id });
                }
                byte[] dek = _cryptographyService.DecryptRsa(storedItemToUpdate.EncryptedDekForOwner, ownerPrivateKey);
                _logger.LogDebug("Edit POST (Save): DEK decrypted for StoredData ID {DataId}. DEK length: {DekLength}", model.Id, dek.Length);

                // 6. Оновлюємо назву запису
                storedItemToUpdate.DataName = model.DataName;
                bool contentActuallyChanged = false; // Прапорець, чи дійсно змінився вміст або файл

                // 7. Перевіряємо, чи змінився вміст (текст або файл)
                if (storedItemToUpdate.DataType == StorageEntryType.Text)
                {
                    if (model.TextContent != null)
                    {
                        _logger.LogInformation("Edit POST (Save): Updating text content for StoredData ID {DataId}.", model.Id);
                        byte[] newContentBytes = Encoding.UTF8.GetBytes(model.TextContent); // model.TextContent містить новий/змінений текст
                                                                                            // Важливо: генеруємо новий IV для кожного шифрування, навіть якщо ключ той самий
                        var (newEncryptedContent, newIv) = _cryptographyService.EncryptAes(newContentBytes, dek);

                        storedItemToUpdate.EncryptedContentBytes = newEncryptedContent;
                        storedItemToUpdate.InitializationVector = newIv;

                        // Очищаємо файлові поля, це текстовий запис
                        storedItemToUpdate.OriginalFileName = null;
                        storedItemToUpdate.ContentType = null;
                        storedItemToUpdate.FileSize = null;
                        contentActuallyChanged = true;
                    }
                }
                else if (storedItemToUpdate.DataType == StorageEntryType.File)
                {
                    if (model.NewFileToUpload != null && model.NewFileToUpload.Length > 0)
                    {
                        _logger.LogInformation("Edit POST (Save): Replacing file for StoredData ID {DataId} with new file {FileName}.", model.Id, model.NewFileToUpload.FileName);
                        using (var memoryStream = new MemoryStream())
                        {
                            await model.NewFileToUpload.CopyToAsync(memoryStream);
                            byte[] newFileBytes = memoryStream.ToArray();

                            // генеруємо новий IV
                            var (newEncryptedContent, newIv) = _cryptographyService.EncryptAes(newFileBytes, dek);

                            storedItemToUpdate.EncryptedContentBytes = newEncryptedContent;
                            storedItemToUpdate.InitializationVector = newIv;
                            storedItemToUpdate.OriginalFileName = model.NewFileToUpload.FileName;
                            storedItemToUpdate.ContentType = model.NewFileToUpload.ContentType;
                            storedItemToUpdate.FileSize = model.NewFileToUpload.Length;
                            contentActuallyChanged = true;
                        }
                    }
                }

                // Оновлюємо час тільки якщо змінилася назва або вміст
                if (contentActuallyChanged || _context.Entry(storedItemToUpdate).Property(x => x.DataName).IsModified)
                {
                    storedItemToUpdate.Timestamp = DateTime.UtcNow;
                }

                _context.StoredDatas.Update(storedItemToUpdate);
                await _context.SaveChangesAsync();

                // Логування аудиту для успішного редагування
                await _auditService.LogEventAsync(
                    currentUserId,
                    currentUser.Email,
                    AuditEventType.DataModified,
                    $"Оновлено запис: '{storedItemToUpdate.DataName}', ID: {storedItemToUpdate.Id}. Змінено вміст: {contentActuallyChanged}",
                    "StoredData",
                    storedItemToUpdate.Id.ToString()
                );

                TempData["SuccessMessage"] = $"Запис '{storedItemToUpdate.DataName}' успішно оновлено.";
                _logger.LogInformation("Edit POST (Save): StoredData ID {DataId} successfully updated by user {UserId}.", model.Id, currentUserId);
                return RedirectToAction(nameof(Details), new { id = storedItemToUpdate.Id });
            }
            catch (CryptographicException ex)
            {
                _logger.LogError(ex, "Edit POST (Save): Cryptographic error for StoredData ID {DataId}, User {UserId}.", model.Id, currentUserId);
                ModelState.AddModelError(string.Empty, "Виникла криптографічна помилка під час оновлення. Перевірте пароль.");
                // логування аудиту для невдалого редагування через крипто-помилку
                await _auditService.LogEventAsync(currentUserId, currentUser.Email, AuditEventType.DataModificationFailure, // Потрібен тип AuditEventType.DataModificationFailure
                    $"Невдала спроба оновити дані ID: {model.Id}. Причина: Криптографічна помилка.", "StoredData", model.Id.ToString());

            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Edit POST (Save): General error for StoredData ID {DataId}, User {UserId}.", model.Id, currentUserId);
                ModelState.AddModelError(string.Empty, "Виникла неочікувана помилка при оновленні даних.");
                // логування аудиту для невдалого редагування через загальну помилку
                await _auditService.LogEventAsync(currentUserId, currentUser.Email, AuditEventType.DataModificationFailure,
                     $"Невдала спроба оновити дані ID: {model.Id}. Причина: Загальна помилка сервера.", "StoredData", model.Id.ToString());
            }
            finally
            {
                ownerPrivateKey?.Dispose();
            }

            // Потрібно перезавантажити деякі дані для View, оскільки вони могли не зберегтися з POST-запиту
            var originalDataForErrorView = await _context.StoredDatas.AsNoTracking()
                                                .Select(s => new { s.Id, s.OriginalFileName, s.ContentType, s.DataName, s.DataType })
                                                .FirstOrDefaultAsync(s => s.Id == model.Id);
            if (originalDataForErrorView != null)
            {
                // Відновлюємо поля, які могли бути не передані з форми, або які користувач міг змінити, але виникла помилка
                model.OriginalFileName = originalDataForErrorView.OriginalFileName;
                model.ContentType = originalDataForErrorView.ContentType;
                model.DataType = originalDataForErrorView.DataType;
            }
            // Визначаємо, чи потрібно знову показувати запит пароля для завантаження тексту


            ViewBag.DataId = model.Id;
            return View(model);
        }


        // GET: DataStorage
        public async Task<IActionResult> Index(string sortOrder, string currentFilter, string searchTerm, int? pageNumber)
        {
            ViewData["CurrentSort"] = sortOrder;
            ViewData["NameSortParm"] = string.IsNullOrEmpty(sortOrder) || sortOrder == "name_desc" ? "name_asc" : "name_desc";
            ViewData["DateSortParm"] = sortOrder == "date_asc" ? "date_desc" : "date_asc";

            if (searchTerm != null)
            {
                pageNumber = 1; // При новому пошуку завжди переходимо на першу сторінку
            }
            else
            {
                searchTerm = currentFilter;
            }
            ViewData["CurrentFilter"] = searchTerm;

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null) return Unauthorized();

            // --- Початок формування запитів ---
            var results = new List<StoredDataIndexViewModel>();
            var ownedDataQuery = _context.StoredDatas.Where(d => d.OwnerUserId == userId);
            if (!string.IsNullOrEmpty(searchTerm))
            {
                ownedDataQuery = ownedDataQuery.Where(d => (d.DataName != null && d.DataName.Contains(searchTerm)) ||
                                                           (d.OriginalFileName != null && d.OriginalFileName.Contains(searchTerm)));
            }
            var ownedData = await ownedDataQuery
                                    .Select(d => new StoredDataIndexViewModel
                                    {
                                        Id = d.Id,
                                        DataName = d.DataName,
                                        Timestamp = d.Timestamp,
                                        IsOwner = true,
                                        OwnerEmail = "(Ви)",
                                        DataType = d.DataType,
                                        OriginalFileName = d.OriginalFileName,
                                        FileSize = d.FileSize,
                                        ContentType = d.ContentType
                                    })
                                    .ToListAsync();
            results.AddRange(ownedData);

            // 1. Явно оголошуємо тип змінної IQueryable<DataPermission>
            IQueryable<DataPermission> sharedDataPermissionsQuery = _context.DataPermissions
                                                                        .Where(p => p.RecipientUserId == userId);

            // 2. Додаємо Include та ThenInclude. 
            sharedDataPermissionsQuery = sharedDataPermissionsQuery
                                            .Include(p => p.StoredData)
                                            .ThenInclude(sd => sd!.OwnerUser);

            if (!string.IsNullOrEmpty(searchTerm))
            {
                sharedDataPermissionsQuery = sharedDataPermissionsQuery
                    .Where(p =>
                        p.StoredData != null &&
                        (
                            (p.StoredData.DataName != null && p.StoredData.DataName.Contains(searchTerm)) ||
                            (p.StoredData.OriginalFileName != null && p.StoredData.OriginalFileName.Contains(searchTerm))
                        )
                    );
            }

            var sharedDataPermissions = await sharedDataPermissionsQuery.ToListAsync();
            foreach (var permission in sharedDataPermissions)
            {
                if (permission.StoredData != null && permission.StoredData.OwnerUser != null)
                {
                    if (!results.Any(r => r.Id == permission.StoredDataId))
                    {
                        results.Add(new StoredDataIndexViewModel
                        {
                            Id = permission.StoredData.Id,
                            DataName = permission.StoredData.DataName,
                            Timestamp = permission.StoredData.Timestamp,
                            IsOwner = false,
                            OwnerEmail = permission.StoredData.OwnerUser.Email,
                            DataType = permission.StoredData.DataType,
                            OriginalFileName = permission.StoredData.OriginalFileName,
                            FileSize = permission.StoredData.FileSize,
                            ContentType = permission.StoredData.ContentType
                        });
                    }
                }
            }
            // --- Кінець формування запитів ---

            // --- Сортування ---
            switch (sortOrder)
            {
                case "name_desc":
                    results = results.OrderByDescending(r => r.DataType == StorageEntryType.File && !string.IsNullOrEmpty(r.OriginalFileName) ? r.OriginalFileName : r.DataName).ToList();
                    break;
                case "date_asc":
                    results = results.OrderBy(r => r.Timestamp).ToList();
                    break;
                case "date_desc":
                    results = results.OrderByDescending(r => r.Timestamp).ToList();
                    break;
                default: // name_asc (за замовчуванням сортує за назвою)
                    results = results.OrderBy(r => r.DataType == StorageEntryType.File && !string.IsNullOrEmpty(r.OriginalFileName) ? r.OriginalFileName : r.DataName).ToList();
                    break;
            }
            // --- Кінець сортування ---

            // --- ПАГІНАЦІЯ ---
            int pageSize = 5; // Кількість елементів на сторінці

            var paginatedResults = PaginatedList<StoredDataIndexViewModel>.Create(results, pageNumber ?? 1, pageSize);

            return View(paginatedResults); // Передаємо об'єкт PaginatedList у View
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Share(ShareDataViewModel model)
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var currentUser = await _userManager.FindByIdAsync(currentUserId); // Отримуємо поточного користувача (власника)

            if (currentUser == null)
            {
                return Unauthorized();
            }

            // 0. Якщо ModelState не валідний спочатку (наприклад, не обрано отримувача або не введено пароль власника)
            if (!ModelState.IsValid)
            {
                // Потрібно перезавантажити дані для View, подібно до GET-методу Share
                var storedDataForRepopulate = await _context.StoredDatas
                                                    .AsNoTracking()
                                                    .FirstOrDefaultAsync(d => d.Id == model.StoredDataId && d.OwnerUserId == currentUserId);
                if (storedDataForRepopulate == null)
                {
                    TempData["ErrorMessage"] = "Помилка завантаження форми: Дані не знайдено або ви не є власником.";
                    return RedirectToAction(nameof(Index));
                }

                var existingPermissionsDetails = await _context.DataPermissions
                                                .Where(p => p.StoredDataId == model.StoredDataId)
                                                .Include(p => p.RecipientUser)
                                                .Where(p => p.RecipientUser != null)
                                                .Select(p => new ExistingPermissionViewModel { RecipientUserId = p.RecipientUser!.Id, RecipientEmail = p.RecipientUser!.Email })
                                                .ToListAsync();
                model.ExistingPermissions = existingPermissionsDetails;

                var existingRecipientIds = existingPermissionsDetails.Select(epd => epd.RecipientUserId).ToList();
                model.PotentialRecipients = await _userManager.Users
                                            .Where(u => u.Id != currentUserId && !existingRecipientIds.Contains(u.Id) && u.PublicKeyPem != null) // Додано перевірку на PublicKeyPem
                                            .OrderBy(u => u.Email)
                                            .Select(u => new SelectListItem { Value = u.Id, Text = u.Email })
                                            .ToListAsync();
                model.DataName = storedDataForRepopulate.DataName;
                return View(model);
            }

            // 1. Перевірка пароля власника
            var passwordCheck = await _userManager.CheckPasswordAsync(currentUser, model.OwnerPassword);
            if (!passwordCheck)
            {
                ModelState.AddModelError("OwnerPassword", "Неправильний пароль власника.");
                // Перезавантажуємо дані для View
                var storedDataForRepopulate = await _context.StoredDatas.AsNoTracking().FirstOrDefaultAsync(d => d.Id == model.StoredDataId && d.OwnerUserId == currentUserId);
                if (storedDataForRepopulate == null) { TempData["ErrorMessage"] = "Дані не знайдено."; return RedirectToAction(nameof(Index)); }
                var existingPermissionsDetails = await _context.DataPermissions.Where(p => p.StoredDataId == model.StoredDataId).Include(p => p.RecipientUser).Where(p => p.RecipientUser != null).Select(p => new ExistingPermissionViewModel { RecipientUserId = p.RecipientUser!.Id, RecipientEmail = p.RecipientUser!.Email }).ToListAsync();
                model.ExistingPermissions = existingPermissionsDetails;
                var existingRecipientIds = existingPermissionsDetails.Select(epd => epd.RecipientUserId).ToList();
                model.PotentialRecipients = await _userManager.Users.Where(u => u.Id != currentUserId && !existingRecipientIds.Contains(u.Id) && u.PublicKeyPem != null).OrderBy(u => u.Email).Select(u => new SelectListItem { Value = u.Id, Text = u.Email }).ToListAsync();
                model.DataName = storedDataForRepopulate.DataName;
                return View(model);
            }

            // 2. Отримання даних, якими ділимося, та перевірка, що поточний користувач є власником
            var storedDataToShare = await _context.StoredDatas
                                         .FirstOrDefaultAsync(sd => sd.Id == model.StoredDataId && sd.OwnerUserId == currentUserId);
            if (storedDataToShare == null)
            {
                TempData["ErrorMessage"] = "Помилка: Дані для обміну не знайдено або ви не є їх власником.";
                return RedirectToAction(nameof(Index));
            }
            if (storedDataToShare.EncryptedDekForOwner == null)
            {
                TempData["ErrorMessage"] = "Помилка: Ключ шифрування даних (DEK) для власника відсутній. Неможливо поділитися.";
                return RedirectToAction(nameof(Share), new { id = model.StoredDataId });
            }


            // 3. Отримання інформації про отримувача
            var recipientUser = await _userManager.FindByIdAsync(model.SelectedRecipientUserId!);
            if (recipientUser == null)
            {
                TempData["ErrorMessage"] = "Помилка: Обраного отримувача не знайдено.";
                return RedirectToAction(nameof(Share), new { id = model.StoredDataId });
            }
            if (string.IsNullOrEmpty(recipientUser.PublicKeyPem))
            {
                TempData["ErrorMessage"] = $"Помилка: У користувача {recipientUser.Email} відсутній публічний ключ. Обмін неможливий.";
                return RedirectToAction(nameof(Share), new { id = model.StoredDataId });
            }
            if (recipientUser.Id == currentUserId)
            {
                TempData["ErrorMessage"] = "Ви не можете надати доступ самому собі.";
                return RedirectToAction(nameof(Share), new { id = model.StoredDataId });
            }

            // 4. Перевірка, чи дозвіл вже не було надано раніше
            bool permissionExists = await _context.DataPermissions
                                               .AnyAsync(dp => dp.StoredDataId == model.StoredDataId &&
                                                               dp.RecipientUserId == model.SelectedRecipientUserId);
            if (permissionExists)
            {
                TempData["InfoMessage"] = $"Доступ для користувача {recipientUser.Email} до цих даних вже було надано раніше.";
                return RedirectToAction(nameof(Share), new { id = model.StoredDataId });
            }

            // --- Початок криптографічних операцій для обміну ---
            try
            {
                // 5. Розшифрування приватного ключа власника
                RSA ownerPrivateKey = _cryptographyService.GetDecryptedPrivateKey(
                    currentUser.EncryptedPrivateKeyPem!,
                    currentUser.PrivateKeyEncryptionSalt!,
                    model.OwnerPassword! // Пароль власника, перевірений раніше
                );

                // 6. Розшифрування DEK за допомогою приватного ключа власника
                byte[] dek = _cryptographyService.DecryptRsa(storedDataToShare.EncryptedDekForOwner, ownerPrivateKey);
                ownerPrivateKey.Dispose(); // Звільняємо ресурси приватного ключа власника

                // 7. Отримання та імпорт публічного ключа отримувача
                RSA recipientPublicKey = _cryptographyService.ImportPublicKeyFromPem(recipientUser.PublicKeyPem);

                // 8. Шифрування DEK публічним ключем отримувача
                byte[] encryptedDekForRecipient = _cryptographyService.EncryptRsa(dek, recipientPublicKey);
                recipientPublicKey.Dispose(); // Звільняємо ресурси публічного ключа отримувача

                // 9. Створення та збереження нового дозволу
                var newPermission = new DataPermission
                {
                    StoredDataId = model.StoredDataId,
                    OwnerUserId = currentUserId,
                    RecipientUserId = model.SelectedRecipientUserId!,
                    EncryptedDekForRecipient = encryptedDekForRecipient, // Зберігаємо DEK, зашифрований для отримувача
                    GrantedTimestamp = DateTime.UtcNow
                };

                _context.DataPermissions.Add(newPermission);
                await _context.SaveChangesAsync();

                TempData["SuccessMessage"] = $"Доступ до даних '{storedDataToShare.DataName}' успішно надано користувачеві {recipientUser.Email}.";
                // --- ЛОГУВАННЯ АУДИТУ ---
                await _auditService.LogEventAsync(
                    currentUserId, // Власник, який надає доступ
                    currentUser.Email,
                    AuditEventType.PermissionGranted,
                    $"Надано доступ до даних '{storedDataToShare.DataName}' (ID даних: {storedDataToShare.Id}) " +
                    $"користувачеві {recipientUser.Email} (ID отримувача: {recipientUser.Id}). " +
                    $"ID дозволу: {newPermission.Id}.", // ID самого запису дозволу
                    "DataPermission", // "StoredData" з деталями про дозвіл
                    newPermission.Id.ToString()
                );

                return RedirectToAction(nameof(Share), new { id = model.StoredDataId });
            }
            catch (CryptographicException ex)
            {
                _logger.LogError(ex, "Криптографічна помилка при наданні доступу до даних {DataId} для користувача {RecipientId} від власника {OwnerId}", model.StoredDataId, model.SelectedRecipientUserId, currentUserId);
                TempData["ErrorMessage"] = "Виникла криптографічна помилка при спробі надати доступ. Перевірте правильність вашого пароля або стан ключів.";
                return RedirectToAction(nameof(Share), new { id = model.StoredDataId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Загальна помилка при наданні доступу до даних {DataId} для користувача {RecipientId} від власника {OwnerId}", model.StoredDataId, model.SelectedRecipientUserId, currentUserId);
                TempData["ErrorMessage"] = "Виникла неочікувана помилка при спробі надати доступ.";
                return RedirectToAction(nameof(Share), new { id = model.StoredDataId });
            }
        }


    }
}
