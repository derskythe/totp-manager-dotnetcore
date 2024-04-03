/*
 * This work (Modern Encryption of a String C#, by James Tuley),
 * identified by James Tuley, is free of known copyright restrictions.
 * https://gist.github.com/4336842
 * http://creativecommons.org/publicdomain/mark/1.0/
 */


using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace totp;


internal static class AesThenHmac
{
    private static readonly RandomNumberGenerator _Random = RandomNumberGenerator.Create();

    //Preconfigured Encryption Parameters
    private const int BLOCK_BIT_SIZE = 128;
    private const int KEY_BIT_SIZE = 256;

    //Preconfigured Password Key Derivation Parameters
    private const int SALT_BIT_SIZE = 64;
    private const int ITERATIONS = 10000;
    private const int MIN_PASSWORD_LENGTH = 6; // 12
    private static readonly HashAlgorithmName _HashAlgorithm = HashAlgorithmName.SHA3_512;

    /// <summary>
    /// Helper that generates a random key on each call.
    /// </summary>
    /// <returns></returns>
    public static byte[] NewKey()
    {
        var key = new byte[KEY_BIT_SIZE / 8];
        _Random.GetBytes(key);

        return key;
    }

    /// <summary>
    /// Simple Encryption (AES) then Authentication (HMAC) for a UTF8 Message.
    /// </summary>
    /// <param name="secretMessage">The secret message.</param>
    /// <param name="cryptKey">The crypt key.</param>
    /// <param name="authKey">The auth key.</param>
    /// <param name="nonSecretPayload">(Optional) Non-Secret Payload.</param>
    /// <returns>
    /// Encrypted Message
    /// </returns>
    /// <exception cref="System.ArgumentException">Secret Message Required!;secretMessage</exception>
    /// <remarks>
    /// Adds overhead of (Optional-Payload + BlockSize(16) + Message-Padded-To-Blocksize +  HMac-Tag(32)) * 1.33 Base64
    /// </remarks>
    public static string SimpleEncrypt(
        string secretMessage,
        byte[] cryptKey,
        byte[] authKey,
        byte[] nonSecretPayload = null
    )
    {
        if (string.IsNullOrEmpty(secretMessage))
            throw new ArgumentException("Secret Message Required!", nameof(secretMessage));

        var plainText = Encoding.UTF8.GetBytes(secretMessage);
        var cipherText = SimpleEncrypt(plainText, cryptKey, authKey, nonSecretPayload);

        return Convert.ToBase64String(cipherText);
    }

    /// <summary>
    /// Simple Authentication (HMAC) then Decryption (AES) for a secrets UTF8 Message.
    /// </summary>
    /// <param name="encryptedMessage">The encrypted message.</param>
    /// <param name="cryptKey">The crypt key.</param>
    /// <param name="authKey">The auth key.</param>
    /// <param name="nonSecretPayloadLength">Length of the non secret payload.</param>
    /// <returns>
    /// Decrypted Message
    /// </returns>
    /// <exception cref="System.ArgumentException">Encrypted Message Required!;encryptedMessage</exception>
    public static string SimpleDecrypt(
        string encryptedMessage,
        byte[] cryptKey,
        byte[] authKey,
        int nonSecretPayloadLength = 0
    )
    {
        if (string.IsNullOrWhiteSpace(encryptedMessage))
        {
            throw new ArgumentException("Encrypted Message Required!", nameof(encryptedMessage));
        }

        var cipherText = Convert.FromBase64String(encryptedMessage);
        var plainText = SimpleDecrypt(cipherText, cryptKey, authKey, nonSecretPayloadLength);

        return plainText == null ? null : Encoding.UTF8.GetString(plainText);
    }

    /// <summary>
    /// Simple Encryption (AES) then Authentication (HMAC) of a UTF8 message
    /// using Keys derived from a Password (PBKDF2).
    /// </summary>
    /// <param name="secretMessage">The secret message.</param>
    /// <param name="password">The password.</param>
    /// <param name="nonSecretPayload">The non secret payload.</param>
    /// <returns>
    /// Encrypted Message
    /// </returns>
    /// <exception cref="System.ArgumentException">password</exception>
    /// <remarks>
    /// Significantly less secure than using random binary keys.
    /// Adds additional non secret payload for key generation parameters.
    /// </remarks>
    public static string SimpleEncryptWithPassword(
        string secretMessage,
        string password,
        byte[] nonSecretPayload = null
    )
    {
        if (string.IsNullOrEmpty(secretMessage))
        {
            throw new ArgumentException("Secret Message Required!", nameof(secretMessage));
        }

        var plainText = Encoding.UTF8.GetBytes(secretMessage);
        var cipherText = SimpleEncryptWithPassword(plainText, password, nonSecretPayload);

        return Convert.ToBase64String(cipherText);
    }

    /// <summary>
    /// Simple Authentication (HMAC) and then Descryption (AES) of a UTF8 Message
    /// using keys derived from a password (PBKDF2).
    /// </summary>
    /// <param name="encryptedMessage">The encrypted message.</param>
    /// <param name="password">The password.</param>
    /// <param name="nonSecretPayloadLength">Length of the non secret payload.</param>
    /// <returns>
    /// Decrypted Message
    /// </returns>
    /// <exception cref="System.ArgumentException">Encrypted Message Required!;encryptedMessage</exception>
    /// <remarks>
    /// Significantly less secure than using random binary keys.
    /// </remarks>
    public static string SimpleDecryptWithPassword(
        string encryptedMessage,
        string password,
        int nonSecretPayloadLength = 0
    )
    {
        if (string.IsNullOrWhiteSpace(encryptedMessage))
        {
            throw new ArgumentException("Encrypted Message Required!", nameof(encryptedMessage));
        }

        var cipherText = Convert.FromBase64String(encryptedMessage);
        var plainText = SimpleDecryptWithPassword(cipherText, password, nonSecretPayloadLength);

        return plainText == null ? null : Encoding.UTF8.GetString(plainText);
    }

    /// <summary>
    /// Simple Encryption(AES) then Authentication (HMAC) for a UTF8 Message.
    /// </summary>
    /// <param name="secretMessage">The secret message.</param>
    /// <param name="cryptKey">The crypt key.</param>
    /// <param name="authKey">The auth key.</param>
    /// <param name="nonSecretPayload">(Optional) Non-Secret Payload.</param>
    /// <returns>
    /// Encrypted Message
    /// </returns>
    /// <remarks>
    /// Adds overhead of (Optional-Payload + BlockSize(16) + Message-Padded-To-Blocksize +  HMac-Tag(32)) * 1.33 Base64
    /// </remarks>
    private static byte[] SimpleEncrypt(
        byte[] secretMessage,
        byte[] cryptKey,
        byte[] authKey,
        byte[] nonSecretPayload = null
    )
    {
        //User Error Checks
        if (cryptKey is not { Length: KEY_BIT_SIZE / 8 })
        {
            throw new ArgumentException($"Key needs to be {KEY_BIT_SIZE} bit!", nameof(cryptKey));
        }

        if (authKey is not { Length: KEY_BIT_SIZE / 8 })
        {
            throw new ArgumentException($"Key needs to be {KEY_BIT_SIZE} bit!", nameof(authKey));
        }

        if (secretMessage == null || secretMessage.Length < 1)
        {
            throw new ArgumentException("Secret Message Required!", nameof(secretMessage));
        }

        //non-secret payload optional
        nonSecretPayload ??= new byte[] { };

        byte[] cipherText;
        byte[] iv;

        using (var aes = Aes.Create())
        {
            aes.KeySize = KEY_BIT_SIZE;
            aes.BlockSize = BLOCK_BIT_SIZE;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;


            //Use random IV
            aes.GenerateIV();
            iv = aes.IV;

            using (var encrypter = aes.CreateEncryptor(cryptKey, iv))
            using (var cipherStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(cipherStream, encrypter, CryptoStreamMode.Write))
                using (var binaryWriter = new BinaryWriter(cryptoStream))
                {
                    //Encrypt Data
                    binaryWriter.Write(secretMessage);
                }

                cipherText = cipherStream.ToArray();
            }
        }

        //Assemble encrypted message and add authentication
        using (var hmac = new HMACSHA256(authKey))
        using (var encryptedStream = new MemoryStream())
        {
            using (var binaryWriter = new BinaryWriter(encryptedStream))
            {
                //Prepend non-secret payload if any
                binaryWriter.Write(nonSecretPayload);

                //Prepend IV
                binaryWriter.Write(iv);

                //Write Ciphertext
                binaryWriter.Write(cipherText);
                binaryWriter.Flush();

                //Authenticate all data
                var tag = hmac.ComputeHash(encryptedStream.ToArray());

                //Postpend tag
                binaryWriter.Write(tag);
            }

            return encryptedStream.ToArray();
        }
    }

    /// <summary>
    /// Simple Authentication (HMAC) then Decryption (AES) for a secrets UTF8 Message.
    /// </summary>
    /// <param name="encryptedMessage">The encrypted message.</param>
    /// <param name="cryptKey">The crypt key.</param>
    /// <param name="authKey">The auth key.</param>
    /// <param name="nonSecretPayloadLength">Length of the non secret payload.</param>
    /// <returns>Decrypted Message</returns>
    private static byte[] SimpleDecrypt(
        byte[] encryptedMessage,
        byte[] cryptKey,
        byte[] authKey,
        int nonSecretPayloadLength = 0
    )
    {
        //Basic Usage Error Checks
        if (cryptKey is not { Length: KEY_BIT_SIZE / 8 })
        {
            throw new ArgumentException($"CryptKey needs to be {KEY_BIT_SIZE} bit!", nameof(cryptKey));
        }

        if (authKey is not { Length: KEY_BIT_SIZE / 8 })
        {
            throw new ArgumentException($"AuthKey needs to be {KEY_BIT_SIZE} bit!", nameof(authKey));
        }

        if (encryptedMessage == null || encryptedMessage.Length == 0)
        {
            throw new ArgumentException("Encrypted Message Required!", nameof(encryptedMessage));
        }

        using var hmac = new HMACSHA256(authKey);

        var sentTag = new byte[hmac.HashSize / 8];

        //Calculate Tag
        var calcTag = hmac.ComputeHash(encryptedMessage, 0, encryptedMessage.Length - sentTag.Length);
        const int ivLength = BLOCK_BIT_SIZE / 8;

        //if message length is to small just return null
        if (encryptedMessage.Length < sentTag.Length + nonSecretPayloadLength + ivLength)
        {
            Console.WriteLine("Message length is incorrect!");

            return Array.Empty<byte>();
        }

        //Grab Sent Tag
        Array.Copy(encryptedMessage,
                   encryptedMessage.Length - sentTag.Length,
                   sentTag,
                   0,
                   sentTag.Length
        );

        //Compare Tag with constant time comparison
        var compare = 0;

        for (var i = 0; i < sentTag.Length; i++)
        {
            compare |= sentTag[i] ^ calcTag[i];
        }

        //if message doesn't authenticate return null
        if (compare != 0)
        {
            Console.WriteLine("Message failed authentication!");

            return Array.Empty<byte>();
        }

        using var aes = Aes.Create();

        aes.KeySize = KEY_BIT_SIZE;
        aes.BlockSize = BLOCK_BIT_SIZE;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        //Grab IV from message
        var iv = new byte[ivLength];
        Array.Copy(encryptedMessage, nonSecretPayloadLength, iv, 0, iv.Length);

        using var decrypter = aes.CreateDecryptor(cryptKey, iv);
        using var plainTextStream = new MemoryStream();

        using (var decrypterStream = new CryptoStream(plainTextStream, decrypter, CryptoStreamMode.Write))
        using (var binaryWriter = new BinaryWriter(decrypterStream))
        {
            //Decrypt Cipher Text from Message
            binaryWriter.Write(
                encryptedMessage,
                nonSecretPayloadLength  + iv.Length,
                encryptedMessage.Length - nonSecretPayloadLength - iv.Length - sentTag.Length
            );
        }

        //Return Plain Text
        return plainTextStream.ToArray();
    }

    /// <summary>
    /// Simple Encryption (AES) then Authentication (HMAC) of a UTF8 message
    /// using Keys derived from a Password (PBKDF2)
    /// </summary>
    /// <param name="secretMessage">The secret message.</param>
    /// <param name="password">The password.</param>
    /// <param name="nonSecretPayload">The non secret payload.</param>
    /// <returns>
    /// Encrypted Message
    /// </returns>
    /// <exception cref="System.ArgumentException">Must have a password of minimum length;password</exception>
    /// <remarks>
    /// Significantly less secure than using random binary keys.
    /// Adds additional non secret payload for key generation parameters.
    /// </remarks>
    private static byte[] SimpleEncryptWithPassword(byte[] secretMessage, string password, byte[] nonSecretPayload = null)
    {
        nonSecretPayload ??= new byte[] { };

        //User Error Checks
        if (string.IsNullOrWhiteSpace(password) || password.Length < MIN_PASSWORD_LENGTH)
        {
            throw new ArgumentException($"Must have a password of at least {MIN_PASSWORD_LENGTH} characters!",
                                        nameof(password)
            );
        }

        if (secretMessage == null || secretMessage.Length == 0)
        {
            throw new ArgumentException("Secret Message Required!", nameof(secretMessage));
        }

        var payload = new byte[((SALT_BIT_SIZE / 8) * 2) + nonSecretPayload.Length];

        Array.Copy(nonSecretPayload, payload, nonSecretPayload.Length);
        int payloadIndex = nonSecretPayload.Length;

        byte[] cryptKey;
        byte[] authKey;

        //Use Random Salt to prevent pre-generated weak password attacks.
        using (var generator = new Rfc2898DeriveBytes(password, SALT_BIT_SIZE / 8, ITERATIONS, _HashAlgorithm))
        {
            var salt = generator.Salt;

            //Generate Keys
            cryptKey = generator.GetBytes(KEY_BIT_SIZE / 8);

            //Create Non Secret Payload
            Array.Copy(salt, 0, payload, payloadIndex, salt.Length);
            payloadIndex += salt.Length;
        }

        //Deriving separate key, might be less efficient than using HKDF,
        //but now compatible with RNEncryptor which had a very similar wireformat and requires less code than HKDF.
        using (var generator = new Rfc2898DeriveBytes(password, SALT_BIT_SIZE / 8, ITERATIONS, _HashAlgorithm))
        {
            var salt = generator.Salt;

            //Generate Keys
            authKey = generator.GetBytes(KEY_BIT_SIZE / 8);

            //Create Rest of Non Secret Payload
            Array.Copy(salt, 0, payload, payloadIndex, salt.Length);
        }

        return SimpleEncrypt(secretMessage, cryptKey, authKey, payload);
    }

    /// <summary>
    /// Simple Authentication (HMAC) and then Descryption (AES) of a UTF8 Message
    /// using keys derived from a password (PBKDF2).
    /// </summary>
    /// <param name="encryptedMessage">The encrypted message.</param>
    /// <param name="password">The password.</param>
    /// <param name="nonSecretPayloadLength">Length of the non secret payload.</param>
    /// <returns>
    /// Decrypted Message
    /// </returns>
    /// <exception cref="System.ArgumentException">Must have a password of minimum length;password</exception>
    /// <remarks>
    /// Significantly less secure than using random binary keys.
    /// </remarks>
    private static byte[] SimpleDecryptWithPassword(byte[] encryptedMessage, string password, int nonSecretPayloadLength = 0)
    {
        //User Error Checks
        if (string.IsNullOrWhiteSpace(password) || password.Length < MIN_PASSWORD_LENGTH)
            throw new ArgumentException($"Must have a password of at least {MIN_PASSWORD_LENGTH} characters!",
                                        nameof(password)
            );

        if (encryptedMessage == null || encryptedMessage.Length == 0)
            throw new ArgumentException("Encrypted Message Required!", nameof(encryptedMessage));

        var cryptSalt = new byte[SALT_BIT_SIZE / 8];
        var authSalt = new byte[SALT_BIT_SIZE  / 8];

        //Grab Salt from Non-Secret Payload
        Array.Copy(encryptedMessage,
                   nonSecretPayloadLength,
                   cryptSalt,
                   0,
                   cryptSalt.Length
        );

        Array.Copy(encryptedMessage,
                   nonSecretPayloadLength + cryptSalt.Length,
                   authSalt,
                   0,
                   authSalt.Length
        );

        byte[] cryptKey;
        byte[] authKey;

        //Generate crypt key
        using (var generator = new Rfc2898DeriveBytes(password,
                                                      cryptSalt,
                                                      ITERATIONS,
                                                      _HashAlgorithm
               ))
        {
            cryptKey = generator.GetBytes(KEY_BIT_SIZE / 8);
        }

        //Generate auth key
        using (var generator = new Rfc2898DeriveBytes(password,
                                                      authSalt,
                                                      ITERATIONS,
                                                      _HashAlgorithm
               ))
        {
            authKey = generator.GetBytes(KEY_BIT_SIZE / 8);
        }

        return SimpleDecrypt(encryptedMessage, cryptKey, authKey, cryptSalt.Length + authSalt.Length + nonSecretPayloadLength);
    }
}
