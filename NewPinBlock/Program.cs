using PinKey;
using System.IO;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Security.Principal;
using System.Linq;

namespace PinKey
{
    class Program
    {
        private static readonly byte[] StaticAesKey = new byte[]
        {
             0x4B, 0x61, 0x33, 0x5F, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x4B, 0x65, 0x79, 0x31, 0x32, 0x33,
             0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49
        };

        private static readonly byte[] StaticHmacKey = new byte[]
        {
             0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74, 0x4D, 0x65, 0x5F, 0x48, 0x4D, 0x41, 0x43, 0x4B, 0x65,
             0x79, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30, 0x58, 0x59, 0x5A, 0x5B, 0x5C
        };

        public static string DecryptPassword(string encryptedDataString, byte[] aesKey, byte[] hmacKey, byte[] associatedData = null)
        {
            if (string.IsNullOrEmpty(encryptedDataString))
                throw new ArgumentNullException(nameof(encryptedDataString), "Encrypted data string cannot be null or empty.");
            if (aesKey == null || aesKey.Length != 32)
                throw new ArgumentException("AES key must be 32 bytes (256 bits).", nameof(aesKey));
            if (hmacKey == null || hmacKey.Length != 32)
                throw new ArgumentException("HMAC key must be 32 bytes (256 bits).", nameof(hmacKey));

            string[] parts = encryptedDataString.Split(':');
            if (parts.Length != 3)
                throw new FormatException("Encrypted data is not in the expected HMAC:IV:Ciphertext format (separated by colons).");

            byte[] storedHmac = Convert.FromBase64String(parts[0]);
            byte[] iv = Convert.FromBase64String(parts[1]);
            byte[] encryptedBytes = Convert.FromBase64String(parts[2]);

            byte[] dataToMac;
            if (associatedData != null && associatedData.Length > 0)
            {
                dataToMac = new byte[associatedData.Length + iv.Length + encryptedBytes.Length];
                Buffer.BlockCopy(associatedData, 0, dataToMac, 0, associatedData.Length);
                Buffer.BlockCopy(iv, 0, dataToMac, associatedData.Length, iv.Length);
                Buffer.BlockCopy(encryptedBytes, 0, dataToMac, associatedData.Length + iv.Length, encryptedBytes.Length);
            }
            else
            {
                dataToMac = new byte[iv.Length + encryptedBytes.Length];
                Buffer.BlockCopy(iv, 0, dataToMac, 0, iv.Length);
                Buffer.BlockCopy(encryptedBytes, 0, dataToMac, iv.Length, encryptedBytes.Length);
            }

            using (HMACSHA256 hmacAlg = new HMACSHA256(hmacKey))
            {
                byte[] computedHmac = hmacAlg.ComputeHash(dataToMac);

                if (!CompareBytes(storedHmac, computedHmac))
                {
                    throw new CryptographicException("HMAC verification failed. Data may have been tampered with or incorrect keys.");
                }
            }

            string plainText = null;
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.KeySize = 256;
                aesAlg.BlockSize = 128;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                aesAlg.Key = aesKey;
                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(encryptedBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plainText = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plainText;
        }
        private static bool CompareBytes(byte[] a, byte[] b)
        {
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;

            int result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }

        public static string EncryptPassword(string plainText, byte[] aesKey, byte[] hmacKey, byte[] associatedData = null)
        {
            if (plainText == null || plainText.Length == 0)
                throw new ArgumentNullException(nameof(plainText));
            if (aesKey == null || aesKey.Length != 32)
                throw new ArgumentException("AES key must be 32 bytes (256 bits).", nameof(aesKey));
            if (hmacKey == null || hmacKey.Length != 32)
                throw new ArgumentException("HMAC key must be 32 bytes (256 bits).", nameof(hmacKey));

            byte[] encryptedBytes;
            byte[] iv;

            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.KeySize = 256;
                aesAlg.BlockSize = 128;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                aesAlg.Key = aesKey;
                aesAlg.GenerateIV();
                iv = aesAlg.IV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encryptedBytes = msEncrypt.ToArray();
                    }
                }
            }

            byte[] dataToMac;
            if (associatedData != null && associatedData.Length > 0)
            {
                dataToMac = new byte[associatedData.Length + iv.Length + encryptedBytes.Length];
                Buffer.BlockCopy(associatedData, 0, dataToMac, 0, associatedData.Length);
                Buffer.BlockCopy(iv, 0, dataToMac, associatedData.Length, iv.Length);
                Buffer.BlockCopy(encryptedBytes, 0, dataToMac, associatedData.Length + iv.Length, encryptedBytes.Length);
            }
            else
            {
                dataToMac = new byte[iv.Length + encryptedBytes.Length];
                Buffer.BlockCopy(iv, 0, dataToMac, 0, iv.Length);
                Buffer.BlockCopy(encryptedBytes, 0, dataToMac, iv.Length, encryptedBytes.Length);
            }

            byte[] hmac;
            using (HMACSHA256 hmacAlg = new HMACSHA256(hmacKey))
            {
                hmac = hmacAlg.ComputeHash(dataToMac);
            }

            return $"{Convert.ToBase64String(hmac)}:{Convert.ToBase64String(iv)}:{Convert.ToBase64String(encryptedBytes)}";
        }
        static void Main(string[] args)
        {
            Console.WriteLine("--- AES-256-CBC with HMAC-SHA256 Utility ---");
            Console.WriteLine("!!! WARNING: Using static/hardcoded keys is a severe security risk for production !!!\n");
            WindowsIdentity currentUser = WindowsIdentity.GetCurrent();
            Console.WriteLine($"{currentUser.Name}");

            while (true)
            {
                Console.WriteLine("\nChoose an option:");
                Console.WriteLine("1. Encrypt a string");
                Console.WriteLine("2. Decrypt a string");
                Console.WriteLine("3. Exit");
                Console.Write("Enter your choice (1, 2, or 3): ");

                string option = Console.ReadLine();
                Console.WriteLine(); 

                switch (option)
                {
                    case "1":
                        HandleEncryption();
                        break;
                    case "2":
                        HandleDecryption();
                        break;
                    case "3":
                        Console.WriteLine("Exiting application. Goodbye!");
                        return;
                    default:
                        Console.WriteLine("Invalid option. Please enter 1, 2, or 3.");
                        break;
                }
            }
        }

        private static void HandleEncryption()
        {
            Console.WriteLine("--- Encryption Menu ---");
            Console.Write("Enter the string you want to encrypt: ");
            string plainText = Console.ReadLine();

            byte[] aesKey = GetKeyInput("AES Decryption Key (Base64) or leave empty for default: ", StaticAesKey, "AesKey");
            byte[] hmacKey = GetKeyInput("HMAC Decryption Key (Base64) or leave empty for default: ", StaticHmacKey, "HmacKey");

            Console.Write("Enter associated data (e.g., username, optional, leave empty if none): ");
            string associatedDataString = Console.ReadLine();
            byte[] associatedDataBytes = string.IsNullOrEmpty(associatedDataString) ? null : Encoding.UTF8.GetBytes(associatedDataString);

            try
            {
                string encryptedValue = EncryptPassword(plainText, aesKey, hmacKey, associatedDataBytes);
                Console.WriteLine("\n--- Encryption Result ---");
                Console.WriteLine($"Original String: {plainText}");
                Console.WriteLine($"Associated Data: {(associatedDataString ?? "[None]")}");
                Console.WriteLine($"Encrypted String (HMAC:IV:Ciphertext Base64): {encryptedValue}");
                Console.WriteLine("\nRemember to store this encrypted string securely, along with the associated data and the keys used for decryption.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nERROR during encryption: {ex.Message}");
                Console.WriteLine("Please ensure your keys are valid 32-byte Base64 strings if you provided custom keys.");
            }
        }

        private static void HandleDecryption()
        {
            Console.WriteLine("--- Decryption Menu ---");
            Console.Write("Enter the encrypted string (HMAC:IV:Ciphertext Base64): ");
            string encryptedString = Console.ReadLine();

            byte[] aesKey = GetKeyInput("AES Decryption Key (Base64) or leave empty for default: ", StaticAesKey, "AesKey");
            byte[] hmacKey = GetKeyInput("HMAC Decryption Key (Base64) or leave empty for default: ", StaticHmacKey, "HmacKey");

            Console.Write("Enter associated data (e.g., username, optional, leave empty if none): ");
            string associatedDataString = Console.ReadLine();
            byte[] associatedDataBytes = string.IsNullOrEmpty(associatedDataString) ? null : Encoding.UTF8.GetBytes(associatedDataString);

            try
            {
                string decryptedValue = DecryptPassword(encryptedString, aesKey, hmacKey, associatedDataBytes);
                Console.WriteLine("\n--- Decryption Result ---");
                Console.WriteLine($"Encrypted String: {encryptedString}");
                Console.WriteLine($"Associated Data: {(associatedDataString ?? "[None]")}");
                Console.WriteLine($"Decrypted String: {decryptedValue}");
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine($"\nERROR during decryption: {ex.Message}");
                Console.WriteLine("This often means the data was tampered with, or the wrong key/associated data was used.");
            }
            catch (FormatException ex)
            {
                Console.WriteLine($"\nERROR: Invalid input format for encrypted string: {ex.Message}");
                Console.WriteLine("Please ensure the encrypted string is in 'HMAC_Base64:IV_Base64:Ciphertext_Base64' format.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nAn unexpected ERROR occurred during decryption: {ex.Message}");
                Console.WriteLine("Please ensure your keys are valid 32-byte Base64 strings if you provided custom keys.");
            }
        }

        private static byte[] GetKeyInput(string prompt, byte[] defaultKey, string keyName)
        {
            Console.Write(prompt);
            string keyInput = Console.ReadLine();

            // Priority 1: User input
            if (!string.IsNullOrEmpty(keyInput))
            {
                try
                {
                    byte[] customKey = Convert.FromBase64String(keyInput);
                    if (customKey.Length == 32)
                    {
                        Console.WriteLine("Using key from user input.");
                        return customKey;
                    }
                    Console.WriteLine("Warning: Custom key length is not 32 bytes (256 bits). Falling back to next priority.");
                }
                catch (FormatException)
                {
                    Console.WriteLine("Warning: Invalid Base64 format for custom key. Falling back to next priority.");
                }
            }

            // Priority 2: File key
            try
            {
                string filePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "keys.config");
                if (File.Exists(filePath))
                {
                    string keyLine = File.ReadAllLines(filePath)
               .FirstOrDefault(l => l.Trim().StartsWith(keyName + ":"));

                    if (keyLine != null)
                    {
                        int equalsIndex = keyLine.IndexOf(':');
                        if (equalsIndex != -1)
                        {
                            string base64Key = keyLine.Substring(equalsIndex + 1).Trim();
                            if (base64Key.Length == 44)
                            {
                                byte[] fileKey = Convert.FromBase64String(base64Key);
                                if (fileKey.Length == 32)
                                {
                                    return fileKey;
                                }
                            }
                            else
                            {
                                Console.WriteLine($"Error: Key '{keyName}' from file has an incorrect length ({base64Key.Length} characters). Expected 44.");
                            }
                        }
                    }
                }
                Console.WriteLine("Warning: Key not found in file or file doesn't exist. Falling back to default key.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Error reading key from file: {ex.Message}. Falling back to default key.");
            }

            // Priority 3: Hardcoded default
            Console.WriteLine("Using default static key.");
            return defaultKey;
        }
        private static byte[] GetKeyInput1(string prompt, byte[] defaultKey)
        {
            Console.Write(prompt);
            string keyInput = Console.ReadLine();
            if (string.IsNullOrEmpty(keyInput))
            {
                Console.WriteLine("Using default static key.");
                return defaultKey;
            }
            else
            {
                try
                {
                    byte[] customKey = Convert.FromBase64String(keyInput);
                    if (customKey.Length != 32)
                    {
                        Console.WriteLine("Warning: Custom key length is not 32 bytes (256 bits). Using default key instead.");
                        return defaultKey;
                    }
                    return customKey;
                }
                catch (FormatException)
                {
                    Console.WriteLine("Warning: Invalid Base64 format for custom key. Using default key instead.");
                    return defaultKey;
                }
            }
        }
    }
}
