using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.Extensions.Logging;

namespace SecureDataSharing.Services
{
    public class CryptographyService : ICryptographyService
    {
        private readonly ILogger<CryptographyService> _logger;

        public CryptographyService(ILogger<CryptographyService> logger)
        {
            _logger = logger;
        }

        public RSA GetDecryptedPrivateKey(string encryptedPrivateKeyPemBase64, string privateKeySaltBase64, string password)
        {
            _logger.LogDebug("Attempting to get decrypted private key. Salt (Base64 provided): {SaltProvided}",
                string.IsNullOrEmpty(privateKeySaltBase64) ? "NULL_OR_EMPTY" : privateKeySaltBase64.Substring(0, Math.Min(10, privateKeySaltBase64.Length)) + "...");
            _logger.LogDebug("Encrypted Private Key (Base64 prefix provided): {EncryptedPKPrefix}",
                string.IsNullOrEmpty(encryptedPrivateKeyPemBase64) ? "NULL_OR_EMPTY" : encryptedPrivateKeyPemBase64.Substring(0, Math.Min(30, encryptedPrivateKeyPemBase64.Length)) + "...");

            if (string.IsNullOrEmpty(encryptedPrivateKeyPemBase64))
            {
                _logger.LogError("GetDecryptedPrivateKey: Encrypted private key (Base64) is null or empty.");
                throw new ArgumentException("Зашифрований приватний ключ (Base64) не може бути порожнім.", nameof(encryptedPrivateKeyPemBase64));
            }
            if (string.IsNullOrEmpty(privateKeySaltBase64))
            {
                _logger.LogError("GetDecryptedPrivateKey: Private key salt (Base64) is null or empty.");
                throw new ArgumentException("Сіль для приватного ключа (Base64) не може бути порожньою.", nameof(privateKeySaltBase64));
            }

            byte[] salt;
            byte[] ivAndEncryptedPrivateKey;

            try
            {
                salt = Convert.FromBase64String(privateKeySaltBase64);
                ivAndEncryptedPrivateKey = Convert.FromBase64String(encryptedPrivateKeyPemBase64);
                _logger.LogDebug("GetDecryptedPrivateKey: Salt and EncryptedPK successfully decoded from Base64. Salt length: {SaltLength}, ivAndEncryptedPK length: {TotalLength}", salt.Length, ivAndEncryptedPrivateKey.Length);
            }
            catch (FormatException ex)
            {
                _logger.LogError(ex, "GetDecryptedPrivateKey: Failed to decode salt or encrypted private key from Base64.");
                throw new CryptographicException("Не вдалося декодувати сіль або зашифрований приватний ключ з Base64.", ex);
            }

            int ivSize = 16; // Стандартний розмір IV для AES (128 біт)
            if (ivAndEncryptedPrivateKey.Length < ivSize)
            {
                _logger.LogError("GetDecryptedPrivateKey: Encrypted private key is too short (length {Length}) to contain IV of size {IvSize}.", ivAndEncryptedPrivateKey.Length, ivSize);
                throw new CryptographicException("Неправильний формат зашифрованого приватного ключа (закороткий для вилучення IV).");
            }

            byte[] iv = new byte[ivSize];
            Buffer.BlockCopy(ivAndEncryptedPrivateKey, 0, iv, 0, ivSize);
            _logger.LogDebug("GetDecryptedPrivateKey: Extracted IV (Base64): {IVBase64}", Convert.ToBase64String(iv));

            byte[] encryptedPrivateKeyBytes = new byte[ivAndEncryptedPrivateKey.Length - ivSize];
            Buffer.BlockCopy(ivAndEncryptedPrivateKey, ivSize, encryptedPrivateKeyBytes, 0, encryptedPrivateKeyBytes.Length);
            _logger.LogDebug("GetDecryptedPrivateKey: Extracted Encrypted Private Key Bytes. Length: {Length}", encryptedPrivateKeyBytes.Length);

            byte[] decryptionKey;
            try
            {
                // Важливо: Пароль тут - це той, що ввів користувач
                decryptionKey = DeriveKeyFromPassword(password, salt);
                _logger.LogDebug("GetDecryptedPrivateKey: Derived decryption key for private key. Length: {KeyLength} bytes.", decryptionKey.Length);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GetDecryptedPrivateKey: Error deriving decryption key from password and salt.");
                throw new CryptographicException("Помилка при генерації ключа дешифрування з пароля та солі.", ex);
            }

            byte[] privateKeyPemBytes;
            try
            {
                // Дешифруємо байти приватного ключа (які є PEM-рядком у байтовому представленні)
                privateKeyPemBytes = DecryptAes(encryptedPrivateKeyBytes, decryptionKey, iv);
                _logger.LogDebug("GetDecryptedPrivateKey: AES decryption of private key successful. PEM Bytes Length: {Length}", privateKeyPemBytes.Length);
            }
            catch (CryptographicException ex_aes)
            {
                _logger.LogError(ex_aes, "GetDecryptedPrivateKey: AES decryption of private key failed. This is typically where 'Padding is invalid' occurs if the key/IV/ciphertext is mismatched.");
                throw new CryptographicException("Помилка безпосередньо при AES дешифруванні приватного ключа (можливо, неправильний пароль/сіль або пошкоджені дані).", ex_aes);
            }
            catch (Exception ex_general_aes)
            {
                _logger.LogError(ex_general_aes, "GetDecryptedPrivateKey: A general error occurred during AES decryption of the private key.");
                throw new CryptographicException("Загальна помилка при AES дешифруванні приватного ключа.", ex_general_aes);
            }

            string privateKeyPem;
            try
            {
                privateKeyPem = Encoding.UTF8.GetString(privateKeyPemBytes);

            }
            catch (Exception ex_encoding)
            {
                _logger.LogError(ex_encoding, "GetDecryptedPrivateKey: Error converting decrypted private key bytes to string.");
                throw new CryptographicException("Помилка при конвертації розшифрованих байт приватного ключа в рядок.", ex_encoding);
            }

            try
            {
                RSA rsaKey = ImportPrivateKeyFromPem(privateKeyPem);
                _logger.LogInformation("GetDecryptedPrivateKey: Successfully decrypted and imported private key.");
                return rsaKey;
            }
            catch (Exception ex_import)
            {
                _logger.LogError(ex_import, "GetDecryptedPrivateKey: Error importing PEM private key after decryption. PEM data might be malformed or not a valid key. PEM (prefix): {PEMPrefix}", privateKeyPem.Substring(0, Math.Min(100, privateKeyPem.Length)));
                throw new CryptographicException("Помилка при імпорті PEM приватного ключа після дешифрування (можливо, ключ пошкоджено або невірний формат).", ex_import);
            }
        }

        public (RSA publicKey, RSA privateKey) GenerateRsaKeyPair(int keySizeInBits = 2048)
        {
            _logger.LogDebug("Generating RSA key pair with size {KeySize} bits.", keySizeInBits);
            var rsa = RSA.Create(keySizeInBits);
            return (rsa, rsa);
        }

        public string ExportPublicKeyToPem(RSA rsaKey)
        {
            _logger.LogDebug("Exporting public key to PEM.");
            return rsaKey.ExportSubjectPublicKeyInfoPem();
        }

        public string ExportPrivateKeyToPem(RSA rsaKey)
        {
            _logger.LogDebug("Exporting private key to PEM.");
            return rsaKey.ExportPkcs8PrivateKeyPem();
        }

        public RSA ImportPublicKeyFromPem(string pem)
        {
            _logger.LogDebug("Importing public key from PEM.");
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return rsa;
        }

        public RSA ImportPrivateKeyFromPem(string pem)
        {
            _logger.LogDebug("Importing private key from PEM.");
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return rsa;
        }

        public byte[] GenerateSalt(int size = 16)
        {
            _logger.LogDebug("Generating salt of size {SaltSize} bytes.", size);
            return RandomNumberGenerator.GetBytes(size);
        }

        public byte[] DeriveKeyFromPassword(string password, byte[] salt, int keySizeInBytes = 32, int iterations = 350000) // Перевірте це значення
        {
            _logger.LogDebug("Deriving key from password. Salt length: {SaltLength}, Key size: {KeySize}, Iterations: {Iterations}", salt.Length, keySizeInBytes, iterations); // Це логування покаже фактичне значення
            return KeyDerivation.Pbkdf2(
                password: password,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA256,
                iterationCount: iterations,
                numBytesRequested: keySizeInBytes);
        }

        public (byte[] Ciphertext, byte[] Iv) EncryptAes(byte[] dataToEncrypt, byte[] key)
        {
            _logger.LogDebug("EncryptAes called. Data length: {DataLength}, Key length: {KeyLength}", dataToEncrypt.Length, key.Length);
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.GenerateIV();
                byte[] iv = aesAlg.IV;
                _logger.LogDebug("EncryptAes: Generated IV (Base64): {IVBase64}", Convert.ToBase64String(iv));

                byte[] encryptedContent;
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msContent = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msContent, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                        csEncrypt.FlushFinalBlock();
                        encryptedContent = msContent.ToArray();
                    }
                }
                _logger.LogDebug("EncryptAes: Encryption complete. Ciphertext length: {CiphertextLength}", encryptedContent.Length);
                return (encryptedContent, iv);
            }
        }

        public byte[] DecryptAes(byte[] encryptedData, byte[] key, byte[] iv)
        {
            _logger.LogDebug("DecryptAes called. Encrypted data length: {DataLength}, Key length: {KeyLength}, IV (Base64): {IVBase64}", encryptedData.Length, key.Length, Convert.ToBase64String(iv));
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(encryptedData))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        List<byte> decryptedBytesList = new List<byte>();
                        int bytesRead;
                        byte[] buffer = new byte[1024];
                        try
                        {
                            _logger.LogDebug("DecryptAes: Starting to read from CryptoStream.");
                            while ((bytesRead = csDecrypt.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                _logger.LogDebug("DecryptAes: Read {BytesRead} bytes from CryptoStream.", bytesRead);
                                for (int i = 0; i < bytesRead; i++) decryptedBytesList.Add(buffer[i]);
                            }
                            _logger.LogDebug("DecryptAes: Finished reading from CryptoStream. Total decrypted bytes: {TotalBytes}", decryptedBytesList.Count);
                        }
                        catch (CryptographicException ex)
                        {
                            _logger.LogError(ex, "DecryptAes: CryptographicException during CryptoStream.Read. This is where 'Padding is invalid' usually occurs.");
                            throw;
                        }
                        return decryptedBytesList.ToArray();
                    }
                }
            }
        }

        public byte[] EncryptRsa(byte[] dataToEncrypt, RSA publicKey)
        {
            _logger.LogDebug("EncryptRsa called. Data length to encrypt: {DataLength}", dataToEncrypt.Length);
            try
            {
                return publicKey.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during RSA encryption.");
                throw;
            }
        }

        public byte[] DecryptRsa(byte[] dataToDecrypt, RSA privateKey)
        {
            _logger.LogDebug("DecryptRsa called. Data length to decrypt: {DataLength}", dataToDecrypt.Length);
            try
            {
                return privateKey.Decrypt(dataToDecrypt, RSAEncryptionPadding.OaepSHA256);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during RSA decryption.");
                throw;
            }
        }
    }
}