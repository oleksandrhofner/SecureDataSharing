using System.Security.Cryptography;

namespace SecureDataSharing.Services
{
    public interface ICryptographyService
    {
        // Для RSA ключів
        (RSA publicKey, RSA privateKey) GenerateRsaKeyPair(int keySizeInBits = 2048);
        string ExportPublicKeyToPem(RSA rsaKey);
        string ExportPrivateKeyToPem(RSA rsaKey);
        RSA ImportPublicKeyFromPem(string pem);
        RSA ImportPrivateKeyFromPem(string pem);
        RSA GetDecryptedPrivateKey(string encryptedPrivateKeyPemBase64, string privateKeySaltBase64, string password);

        // Для симетричного шифрування (приватного ключа)
        byte[] GenerateSalt(int size = 16);
        byte[] DeriveKeyFromPassword(string password, byte[] salt, int keySizeInBytes = 32, int iterations = 350000); // 32 байти = 256 біт
        (byte[] Ciphertext, byte[] Iv) EncryptAes(byte[] dataToEncrypt, byte[] key);
        byte[] DecryptAes(byte[] encryptedData, byte[] key, byte[] iv);
        // Для шифрування/дешифрування DEK за допомогою RSA
        byte[] EncryptRsa(byte[] dataToEncrypt, RSA publicKey);
        byte[] DecryptRsa(byte[] dataToDecrypt, RSA privateKey);
    }
}
