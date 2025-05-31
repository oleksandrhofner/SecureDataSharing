namespace SecureDataSharing.Models.Enums
{
    public enum AuditEventType
    {
        // Автентифікація
        UserLoginSuccess,
        UserLoginFailure,
        UserLogout,
        UserRegistered,
        UserPasswordChanged, //коли реалізується зміна пароля
        // Операції з даними
        DataCreated,
        DataAccessAttempt,// Спроба доступу (перед дешифруванням)
        DataDecryptionSuccess,// Успішне дешифрування даних/файлу
        DataDecryptionFailure,// Невдале дешифрування
        DataDeleted,
        DataModified,
        DataModificationFailure,
        UserPasswordResetSuccess,// Успішне скидання пароля
        UserCryptoKeysClearedAfterReset,// Криптографічні ключі очищено після скидання пароля
        UserCryptoKeysClearanceFailed,// Не вдалося очистити ключі
        UserCryptoKeysGenerated,
        UserCryptoKeysGenerationFailed,
        UserAccountDeleted,
        UserAccountDeletionFailed,
        // Керування доступами
        PermissionGranted,
        PermissionRevoked,
        // Ключі
        PrivateKeyDecryptionSuccess,// Успішне дешифрування приватного RSA ключа
        PrivateKeyDecryptionFailure,// Невдале дешифрування приватного RSA ключа
        // Безпека
        UnauthorizedAccess,
        ApplicationError
    }
}
