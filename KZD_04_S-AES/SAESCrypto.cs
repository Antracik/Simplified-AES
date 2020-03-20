using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace KZD_04_S_AES
{
    public class SAESCryptoService
    {
        #region sBox

        private static readonly byte[] _sBox =
        {
            0x9, 0x4, 0xa, 0xb,
            0xd, 0x1, 0x8, 0x5,
            0x6, 0x2, 0x0, 0x3,
            0xc, 0xe, 0xf, 0x7

        };


        private static readonly byte[] _sBoxI =
        {
            0xa, 0x5, 0x9, 0xb,
            0x1, 0x7, 0x8, 0xf,
            0x6, 0x0, 0x2, 0x3,
            0xc, 0x4, 0xd, 0xe

        };

        #endregion

        #region AddRoundKey

        private void AddRoundKey(ref Block dataBlock, Block keyBlock)
        {
            dataBlock.Nibbles[0].NibbleValue = (byte)(dataBlock.Nibbles[0].NibbleValue ^ keyBlock.Nibbles[0].NibbleValue);
            dataBlock.Nibbles[1].NibbleValue = (byte)(dataBlock.Nibbles[1].NibbleValue ^ keyBlock.Nibbles[1].NibbleValue);
            dataBlock.Nibbles[2].NibbleValue = (byte)(dataBlock.Nibbles[2].NibbleValue ^ keyBlock.Nibbles[2].NibbleValue);
            dataBlock.Nibbles[3].NibbleValue = (byte)(dataBlock.Nibbles[3].NibbleValue ^ keyBlock.Nibbles[3].NibbleValue);
        }

        #endregion

        #region KeyExpansion

        private Block[] KeyExpansion(byte[] key)
        {
            if (key.Length != 2)
                throw new ArgumentOutOfRangeException($"Argument {nameof(key)} should be of length 2");

            //init key array (keys are 16bit each A.K.A. 1 block of 4 nibbles
            Block[] keys = new Block[3]
            {
                //pre round key is the input key given to the function
                new Block(new Nibble[4]
                {
                    new Nibble(key[0], false),
                    new Nibble(key[0]),
                    new Nibble(key[1], false),
                    new Nibble(key[1])
                }),
                new Block(),
                new Block()
            };
            Word[] words = new Word[6];

            words[0].HighNibble = new Nibble(key[0], false);
            words[0].LowNibble = new Nibble(key[0]);

            words[1].HighNibble = new Nibble(key[1], false);
            words[1].LowNibble = new Nibble(key[1]);

            //first round key
            var temp = new Word((byte)(SubWord(RotWord(words[1])).FullValue ^ 0x80));
            words[2] = new Word((byte)(temp.FullValue ^ words[0].FullValue));
            words[3] = new Word((byte)(words[2].FullValue ^ words[1].FullValue));
            keys[1] = new Block(words[2], words[3]);

            temp = new Word((byte)(SubWord(RotWord(words[3])).FullValue ^ 0x30));
            words[4] = new Word((byte)(temp.FullValue ^ words[2].FullValue));
            words[5] = new Word((byte)(words[4].FullValue ^ words[3].FullValue));
            keys[2] = new Block(words[4], words[5]);

            return keys;
        }

        private Word RotWord(Word word)
        {
            Word rotatedWord = new Word();

            rotatedWord.LowNibble = word.HighNibble;
            rotatedWord.HighNibble = word.LowNibble;

            return rotatedWord;
        }

        private Word SubWord(Word word)
        {
            Word subbedWord = new Word();
            var temp = word.LowNibble;
            SubNibble(ref temp);
            subbedWord.LowNibble = temp;

            temp = word.HighNibble;
            SubNibble(ref temp);
            subbedWord.HighNibble = temp;

            return subbedWord;
        }
        #endregion

        #region MixColumns

        private byte GMul(byte a, byte b)
        {
            byte p = 0; // product

            for (int counter = 0; counter < 4; counter++)
            {
                if ((b & 1) != 0) //is high bit (Bbbb) set
                {
                    p ^= a;
                }

                bool isHighBitSet = (a & 0x8) != 0;
                a <<= 1;
                if (isHighBitSet)
                {
                    a ^= 0x13; /* x4 + x + 1 */
                }
                b >>= 1;
            }

            return p;
        }

        private void MixColumns(ref Block block)
        {
            Nibble[] tempArray = new Nibble[4];
            block.Nibbles.CopyTo(tempArray, 0);

            tempArray[0].NibbleValue = (byte)(block.Nibbles[0].NibbleValue ^ GMul(0x4, block.Nibbles[1].NibbleValue));
            tempArray[1].NibbleValue = (byte)(GMul(0x4, block.Nibbles[0].NibbleValue) ^ block.Nibbles[1].NibbleValue);
            tempArray[2].NibbleValue = (byte)(block.Nibbles[2].NibbleValue ^ GMul(0x4, block.Nibbles[3].NibbleValue));
            tempArray[3].NibbleValue = (byte)(GMul(0x4, block.Nibbles[2].NibbleValue) ^ block.Nibbles[3].NibbleValue);

            tempArray.CopyTo(block.Nibbles, 0);
        }

        private void InvMixColumns(ref Block block)
        {
            Nibble[] tempArray = new Nibble[4];
            block.Nibbles.CopyTo(tempArray, 0);

            tempArray[0].NibbleValue = (byte)(GMul(0x9, block.Nibbles[0].NibbleValue) ^ GMul(0x2, block.Nibbles[1].NibbleValue));
            tempArray[1].NibbleValue = (byte)(GMul(0x2, block.Nibbles[0].NibbleValue) ^ GMul(0x9, block.Nibbles[1].NibbleValue));
            tempArray[2].NibbleValue = (byte)(GMul(0x9, block.Nibbles[2].NibbleValue) ^ GMul(0x2, block.Nibbles[3].NibbleValue));
            tempArray[3].NibbleValue = (byte)(GMul(0x2, block.Nibbles[2].NibbleValue) ^ GMul(0x9, block.Nibbles[3].NibbleValue));

            tempArray.CopyTo(block.Nibbles, 0);
        }

        #endregion

        #region ShiftRows
        private void ShiftRows(ref Block nibbleBlock)
        {
            var temp = nibbleBlock.Nibbles[1];
            nibbleBlock.Nibbles[1] = nibbleBlock.Nibbles[3];
            nibbleBlock.Nibbles[3] = temp;
        }

        private void InvShiftRows(ref Block nibbleBlock)
        {
            var temp = nibbleBlock.Nibbles[3];
            nibbleBlock.Nibbles[3] = nibbleBlock.Nibbles[1];
            nibbleBlock.Nibbles[1] = temp;
        }
        #endregion

        #region SubNibbles
        private void SubNibble(ref Nibble nibble)
        {
            int x = nibble.NibbleValue >> 2;
            int y = (byte)(nibble.NibbleValue << 6) >> 6;

            nibble.NibbleValue = _sBox[x * 4 + y];
        }
        private void SubNibble(ref Nibble[] nibbles)
        {
            int length = nibbles.Length;
            for (var i = 0; i < length; i++)
            {
                SubNibble(ref nibbles[i]);
            }
        }

        private void InvSubNibble(ref Nibble nibble)
        {
            int x = nibble.NibbleValue >> 2;
            int y = (byte)(nibble.NibbleValue << 6) >> 6;

            nibble.NibbleValue = _sBoxI[x * 4 + y];
        }

        private void InvSubNibble(ref Nibble[] nibbles)
        {
            int length = nibbles.Length;
            for (var i = 0; i < length; i++)
            {
                InvSubNibble(ref nibbles[i]);
            }
        }

        #endregion

        #region Encryption And Decryption

        public byte[] Encrypt(string plainText, byte[] key)
        {
            int byteLength = Encoding.UTF8.GetByteCount(plainText);
            bool paddingFlag = false;
            if (byteLength % 2 != 0)
            {
                byteLength++;
                paddingFlag = true;
            }

            byte[] cipherText = new byte[byteLength];
            if (paddingFlag)
                cipherText[byteLength - 1] = 0x00;

            Encoding.UTF8.GetBytes(plainText).CopyTo(cipherText, 0);

            for (int i = 0; i < byteLength; i += 2)
            {
                var temp = 
                    EncryptBlock(cipherText.Skip(i)
                    .Take(2)
                    .ToArray(), key);

                cipherText[i] = temp[0];
                cipherText[i + 1] = temp[1];
            }

            return cipherText;
        }

        public string Decrypt(byte[] cipherText, byte[] key)
        {
            byte[] decipheredText = new byte[cipherText.Length];

            int length = cipherText.Length;

            for (int i = 0; i < length; i += 2)
            {
                var temp = 
                    DecryptBlock(cipherText.Skip(i)
                        .Take(2)
                        .ToArray(), key);

                decipheredText[i] = temp[0];
                decipheredText[i + 1] = temp[1];
            }

            if ((byte)decipheredText[length - 1] == 0x00)
                return Encoding.UTF8.GetString(decipheredText, 0, length - 1);

            return Encoding.UTF8.GetString(decipheredText);
        }

        public byte[] EncryptBlock(byte[] block, byte[] key)
        {
            if (block.Length != 2)
                throw new ArgumentOutOfRangeException($"Argument {nameof(block)} must be of length 2");
            if (key.Length != 2)
                throw new ArgumentOutOfRangeException($"Argument {nameof(key)} must be of length 2");

            Block encryptionBlock = new Block(block);
            var keys = KeyExpansion(key);

            //Pre round
            AddRoundKey(ref encryptionBlock, keys[0]);

            //1-st round
            var temp = encryptionBlock.Nibbles;
            SubNibble(ref temp);
            encryptionBlock.Nibbles = temp;
            ShiftRows(ref encryptionBlock);
            MixColumns(ref encryptionBlock);
            AddRoundKey(ref encryptionBlock, keys[1]);

            //2-nd round
            temp = encryptionBlock.Nibbles;
            SubNibble(ref temp);
            encryptionBlock.Nibbles = temp;
            ShiftRows(ref encryptionBlock);
            AddRoundKey(ref encryptionBlock, keys[2]);

            return encryptionBlock.ToBytes();
        }

        public byte[] DecryptBlock(byte[] block, byte[] key)
        {
            if (block.Length != 2)
                throw new ArgumentOutOfRangeException($"Argument {nameof(block)} must be of length 2");
            if (key.Length != 2)
                throw new ArgumentOutOfRangeException($"Argument {nameof(key)} must be of length 2");

            Block decryptionBlock = new Block(block);
            var keys = KeyExpansion(key);

            //Pre round
            AddRoundKey(ref decryptionBlock, keys[2]);

            //1st round
            InvShiftRows(ref decryptionBlock);
            var temp = decryptionBlock.Nibbles;
            InvSubNibble(ref temp);
            decryptionBlock.Nibbles = temp;
            AddRoundKey(ref decryptionBlock, keys[1]);
            InvMixColumns(ref decryptionBlock);

            //2nd round
            InvShiftRows(ref decryptionBlock);
            temp = decryptionBlock.Nibbles;
            InvSubNibble(ref temp);
            AddRoundKey(ref decryptionBlock, keys[0]);

            return decryptionBlock.ToBytes();
        }

        #endregion
        
        #region DataStructures
        private struct Nibble
        {
            public Nibble(byte value, bool lowNibble = true)
            {
                if (lowNibble)
                    NibbleValue = (byte)(value & 0x0F);
                else
                    NibbleValue = (byte)(value >> 4);
            }

            public byte NibbleValue { get; set; }

        }

        private struct Word
        {
            public Word(Nibble highNibble, Nibble lowNibble)
            {
                HighNibble = highNibble;
                LowNibble = lowNibble;
            }

            public Word(byte word)
            {
                HighNibble = new Nibble(word, false);
                LowNibble = new Nibble(word);
            }

            public Nibble HighNibble { get; set; }
            public Nibble LowNibble { get; set; }
            public byte FullValue => (byte)((HighNibble.NibbleValue << 4) | LowNibble.NibbleValue);
        }

        private struct Block
        {
            #region Constructors

            public Block(Nibble[] nibbles)
            {
                if (nibbles.Length != 4)
                    throw new ArgumentOutOfRangeException($"Arguemnt {nameof(nibbles)} should be of length 4");

                _nibbles = nibbles;
            }

            public Block(byte[] block)
            {
                if (block.Length != 2)
                    throw new ArgumentOutOfRangeException($"Arguemnt {nameof(block)} should be of length 2");

                _nibbles = new Nibble[4];

                _nibbles[0] = new Nibble(block[0], false);
                _nibbles[1] = new Nibble(block[0]);
                _nibbles[2] = new Nibble(block[1], false);
                _nibbles[3] = new Nibble(block[1]);
            }

            public Block(Word[] words)
            {
                if (words.Length != 2)
                    throw new ArgumentOutOfRangeException($"Arguemnt {nameof(words)} should be of length 2");

                _nibbles = new Nibble[4];

                _nibbles[0] = words[0].HighNibble;
                _nibbles[1] = words[0].LowNibble;
                _nibbles[2] = words[1].HighNibble;
                _nibbles[3] = words[1].LowNibble;
            }

            public Block(Word wordN1N2, Word wordN3N4)
            {
                _nibbles = new Nibble[4];

                _nibbles[0] = wordN1N2.HighNibble;
                _nibbles[1] = wordN1N2.LowNibble;
                _nibbles[2] = wordN3N4.HighNibble;
                _nibbles[3] = wordN3N4.LowNibble;
            }

            public Block(Nibble n1, Nibble n2, Nibble n3, Nibble n4)
            {
                _nibbles = new Nibble[4];

                _nibbles[0] = n1;
                _nibbles[1] = n2;
                _nibbles[2] = n3;
                _nibbles[3] = n4;

            }

            #endregion   
            public override string ToString()
            {
                return $"{_nibbles[0].NibbleValue:X} | {_nibbles[2].NibbleValue:X}\n" +
                       $"{_nibbles[1].NibbleValue:X} | {_nibbles[3].NibbleValue:X}";
            }

            public byte[] ToBytes()
            {
                return new byte[2]
                {
                    (byte)((_nibbles[0].NibbleValue << 4) | _nibbles[1].NibbleValue ),
                    (byte)((_nibbles[2].NibbleValue << 4) | _nibbles[3].NibbleValue )
                };
            }

            private readonly Nibble[] _nibbles;

            public Nibble[] Nibbles
            {
                get => _nibbles;
                set
                {
                    if (value.Length != 4)
                        throw new ArgumentOutOfRangeException($"Arguemnt {nameof(value)} should be of length 4");
                    value.CopyTo(_nibbles, 0);
                }
            }
        }

    }
        #endregion
}
