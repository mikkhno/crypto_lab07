using System;
using System.Security.Cryptography;
using System.Text;

class RSASignatureSystem
{
    private RSA rsa;

    public RSASignatureSystem()
    {
        rsa = RSA.Create();
    }

    public string ExportPublicKey()
    {
        // Експортуємо публічний ключ у PEM форматі
        return Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
    }

    public string ExportPrivateKey()
    {
        // Експортуємо приватний ключ у PEM форматі
        return Convert.ToBase64String(rsa.ExportPkcs8PrivateKey());
    }

    public byte[] SignMessage(string message)
    {
        // Перетворення повідомлення в байти
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);

        // Створення підпису з використанням SHA-256
        return rsa.SignData(messageBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public bool VerifySignature(string message, byte[] signature, string publicKeyBase64)
    {
        // Імпортуємо публічний ключ
        var rsaVerifier = RSA.Create();
        rsaVerifier.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyBase64), out _);

        // Перетворення повідомлення в байти
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);

        // Перевірка підпису
        return rsaVerifier.VerifyData(messageBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}

class Program
{
    static void Main()
    {
        // Створення системи
        RSASignatureSystem system = new RSASignatureSystem();

        // Генерація ключів
        Console.WriteLine("Generating keys...");
        string privateKey = system.ExportPrivateKey();
        string publicKey = system.ExportPublicKey();

        Console.WriteLine("--- Private Key (Base64):");
        Console.WriteLine(privateKey);
        Console.WriteLine("--- Public Key (Base64):");
        Console.WriteLine(publicKey);

        // Повідомлення
        const string message = "KPI is the best university in Ukraine!";
        Console.WriteLine("--- Message:");
        Console.WriteLine(message);

        // Підписування повідомлення
        Console.WriteLine("Signing message...");
        byte[] signature = system.SignMessage(message);
        string signatureBase64 = Convert.ToBase64String(signature);
        Console.WriteLine("--- Signature (Base64):");
        Console.WriteLine(signatureBase64);

        // Перевірка підпису
        Console.WriteLine("Verifying signature...");
        bool isValid = system.VerifySignature(message, signature, publicKey);
        Console.WriteLine($"Signature verification result: {(isValid ? "Valid" : "Invalid")}");
    }
}
