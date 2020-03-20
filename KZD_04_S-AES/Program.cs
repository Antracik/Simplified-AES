using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace KZD_04_S_AES
{
    public class Program
    {
        
        static void Main()
        {
            //For the moment encryption and decryption is only in UTF8

            //So we can see bulgarian letters
            Console.OutputEncoding = Encoding.UTF8;

            string plainText = "Hello there.\nАх, Генерал Мутафчийски";

            //Example key from the Simplified AES (S-AES) pdf
            byte[] testKey = new byte[2]
            {
                0x24,
                0x75
            };

            var crypt = new SAESCryptoService();

            Console.WriteLine($"Plain text: {plainText}");
            var encryptedBlock = crypt.Encrypt($"{plainText}", testKey);
            Console.WriteLine($"Encrypted: {Encoding.UTF8.GetString(encryptedBlock)}");
            Console.WriteLine($"Decrypted: {crypt.Decrypt(encryptedBlock, testKey)}");

            Console.WriteLine(new string('_', 30));

            //Invalid Key that will throw and exception
            byte[] invalidKey = new byte[3]
            {
                0x24,
                0x75,
                0x75
            };

            try
            {
                Console.WriteLine("Invalid Key that will throw and exception");
                Console.WriteLine("Plain text: Няма да се криптирам, защото ключа ми е невалиден");

                var block = crypt.Encrypt("Няма да се криптирам, защото ключа ми е невалиден", invalidKey);
                crypt.Decrypt(block, invalidKey);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            Console.WriteLine(new string('_', 30));

            byte[] differentKey = new byte[2]
            {
                0x02,
                0xff
            };

            plainText = "La li la le lo";
            Console.WriteLine("Decryption with a key different from the one that the text was encrypted with");
            Console.WriteLine($"Plain text: {plainText}");
            var differentBlock = crypt.Encrypt(plainText, differentKey);
            Console.WriteLine($"Encrypted: {Encoding.UTF8.GetString(encryptedBlock)}");
            Console.WriteLine($"{crypt.Decrypt(differentBlock, testKey)}");
            
            Console.WriteLine(new string('_', 30));
        }

    }
}
