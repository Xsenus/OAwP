using SharpCompress.Archives;
using SharpCompress.Common;
using SharpCompress.Readers;
using System.Security.Cryptography;
using System.Text;

namespace OAwP
{
    internal class Program
    {
        private static string _symbols = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        static async Task Main(string[] args)
        {
            var line = File.ReadAllLines("settings.txt");
            string archivePath = line[0];

            try
            {
                _symbols = line[1];
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error symbols: {ex.Message}");
            }            

            byte[] archiveContent;
            try
            {
                archiveContent = File.ReadAllBytes(archivePath);
            }
            catch (IOException ex)
            {
                Console.WriteLine($"Error reading archive file: {ex.Message}");
                return;
            }

            await Task.Run(() =>
            {
                bool isOpen = false;
                for (int length = 1; length <= 20; length++)
                {
                    foreach (var password in GenerateCombinations(length))
                    {
                        isOpen = OpenArchive(archiveContent, password);

                        if (isOpen)
                        {
                            return;
                        }
                    }
                }
            });
        }

        private static bool OpenArchive(byte[] archiveContent, string password)
        {
            try
            {
                Console.WriteLine($"{password}");

                using (var stream = new MemoryStream(archiveContent))
                using (var reader = ArchiveFactory.Open(stream, new ReaderOptions() { Password = password }))
                {
                    if (reader.Entries.Any())
                    {
                        var firstEntry = reader.Entries.First(entry => entry.IsEncrypted && !entry.IsDirectory);
                        ExtractEntry(firstEntry);
                        Console.WriteLine($"Extracted: {firstEntry.Key}");
                    }
                    else
                    {
                        Console.WriteLine("Archive is empty.");
                    }

                    byte[] key = Encoding.UTF8.GetBytes("0123456789abcdef"); // 128-bit key
                    byte[] iv = Encoding.UTF8.GetBytes("1234567890abcdef"); // 128-bit IV
                    byte[] encrypted = Encrypt(password, key, iv);
                    string base64Encrypted = Convert.ToBase64String(encrypted);

                    Console.WriteLine("Encrypted: {0}", base64Encrypted);
                    File.WriteAllText("password.txt", base64Encrypted);
                    return true;
                }
            }
            catch (Exception ex)
            {
                //Console.WriteLine($"Error: {ex.Message}");
                return false;
            }
        }

        static void ExtractEntry(IArchiveEntry entry)
        {
            if (!entry.IsDirectory)
            {
                entry.WriteToDirectory(".", new ExtractionOptions() { ExtractFullPath = true, Overwrite = true });
            }
        }

        public static IEnumerable<string> GenerateCombinations(int length)
        {
            string symbols = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";

            foreach (var combination in GenerateCombinationsRecursive(length, symbols))
            {
                yield return combination;
            }
        }

        private static IEnumerable<string> GenerateCombinationsRecursive(int length, string symbols, string prefix = "")
        {
            if (length == 0)
            {
                yield return prefix;
                yield break;
            }

            foreach (char c in symbols)
            {
                foreach (var result in GenerateCombinationsRecursive(length - 1, symbols, prefix + c))
                {
                    yield return result;
                }
            }
        }

        public static byte[] Encrypt(string plainText, byte[] key, byte[] iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write, true))
                    {
                        byte[] data = Encoding.UTF8.GetBytes(plainText);
                        csEncrypt.Write(data, 0, data.Length);
                    }
                    return msEncrypt.ToArray();
                }
            }
        }
    }
}
