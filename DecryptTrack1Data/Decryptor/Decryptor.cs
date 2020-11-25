using DecryptTrack1Data.Helpers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace DecryptTrack1Data
{
    /// <summary>
    /// BDK        : 0123456789ABCDEFFEDCBA9876543210
    /// KSN        : FFFF9876543211000620
    /// DERIVED KEY: AC2B83C506DEC9D5E27D51E1D70559E7
    /// </summary>
    public static class Decryptor
    {
        static readonly int RegisterSize = 16;

        static readonly string BDK = "0123456789ABCDEFFEDCBA9876543210";
        static readonly string BDK24 = BDK + BDK.Substring(0, 16);
        static readonly byte[] BDKMASK = ConversionHelper.HexToByteArray(BDK);

        static readonly byte[] KSNZERO = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0, 0x00, 0x00 };
        static readonly byte[] RGMASK = new byte[] { 0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00, 0x00 };
        static readonly byte[] DDMASK = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00 };
        static readonly byte[] PNMASK = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF };

        /// <summary>
        /// TripleDES encrypt FFFF9876543210E0 with the 24 byte "0123456789ABCDEFFEDCBA98765432100123456789ABCDEF" BDK.
        /// The result of this encryption should generate the left register of the IPEK.
        /// </summary>
        /// <param name="ksn"></param>
        /// <returns></returns>
        static byte[] SetKSNZeroCounter(byte[] ksn)
        {
            byte[] zeroksn = new byte[ksn.Length];
            int i = 0;

            foreach (byte value in ksn)
            {
                zeroksn[i] = (byte)(KSNZERO[i] & value);
                i++;
            }

            // Only need the first 8 bytes of the KSN
            byte[] adjustedksn = new byte[ksn.Length - 2];
            Array.Copy(zeroksn, adjustedksn, adjustedksn.Length);

            return adjustedksn;
        }

        /// <summary>
        /// To setup the right register mask:
        /// BDK xor C0C0C0C000000000C0C0C0C000000000
        ///	0123456789ABCDEFFEDCBA9876543210 xor C0C0C0C000000000C0C0C0C000000000
        ///	= C1E385A789ABCDEF3E1C7A5876543210
        ///	8-MSB: C1E385A789ABCDEF
        ///
        ///	Process right register by appending the most significant 8 bytes (8-MSB) to the resulting 24 byte key
        ///	C1E385A789ABCDEF3E1C7A5876543210 + C1E385A789ABCDEF
        ///	= C1E385A789ABCDEF3E1C7A5876543210C1E385A789ABCDEF
        /// </summary>
        /// <returns></returns>
        static byte[] SetRightRegisterMask()
        {
            byte[] rrksn = new byte[BDKMASK.Length];
            int i = 0;

            // BDK ^ RGMASK
            foreach (byte value in BDKMASK)
            {
                rrksn[i] = (byte)(RGMASK[i] ^ value);
                i++;
            }

            // Append 8-MSB from the resulting masked array
            byte[] rightRegister = new byte[BDKMASK.Length + 8];
            Array.Copy(rrksn, rightRegister, rrksn.Length);
            Array.Copy(rrksn, 0, rightRegister, rrksn.Length, 8);

            return rightRegister;
        }

        /// <summary>
        /// The least significant 21 bits of the KSN hold a counter representing how many card swipes have occurred on the device
        /// We look for how many 1's are in the binary representation of that counter for our number of encryption passes to execute
        /// </summary>
        /// <param name="ksn"></param>
        /// <returns></returns>
        static List<int> GetTotalEncryptionPasses(byte[] ksn)
        {
            int passes = 0;

            List<int> totalShifts = new List<int>();
            byte[] counter = new byte[4];
            Array.Copy(ksn, 6, counter, 0, 4);
            Array.Reverse(counter);
            int counterValue = BitConverter.ToInt32(counter, 0) & 0x001FFFFF;

            int i = 0;
            for (int shiftReg = 0x00100000; shiftReg > 0; shiftReg >>= 1, i++)
            {
                if ((shiftReg & counterValue) > 0)
                {
                    //Debug.WriteLine(string.Format("SHIFT REG _: {0:X4}", shiftReg));
                    totalShifts.Add(shiftReg);
                    passes++;
                }
            }
            //Debug.WriteLine($"TOTAL SHIFT: {i}");
            //Debug.WriteLine($"TOTAL PASS : {passes}");

            return totalShifts;
        }

        static byte[] GenerateLeftRegister(byte[] ksnZeroCounter)
        {
            using (var tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.PKCS7;
                tdes.Key = ConversionHelper.HexToByteArray(BDK24);

                using (var transform = tdes.CreateEncryptor())
                {
                    byte[] lrbytes = transform.TransformFinalBlock(ksnZeroCounter, 0, ksnZeroCounter.Length);
                    // Left Register is first 8 bytes
                    byte[] leftRegister = new byte[8];
                    Array.Copy(lrbytes, leftRegister, 8);
                    return leftRegister;
                }
            }
        }

        static byte[] EncryptRegister(byte[] ksnZeroCounter, byte[] maskedKSN)
        {
            using (var tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.PKCS7;
                tdes.Key = maskedKSN;

                using (var transform = tdes.CreateEncryptor())
                {
                    byte[] regBytes = transform.TransformFinalBlock(ksnZeroCounter, 0, ksnZeroCounter.Length);
                    // Left Register is first 8 bytes
                    byte[] register = new byte[8];
                    Array.Copy(regBytes, register, 8);
                    return register;
                }
            }
        }

        static byte[] GenerateRightRegister(byte[] ksnZeroCounter)
        {
            using (var tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.PKCS7;
                tdes.Key = SetRightRegisterMask();

                using (var transform = tdes.CreateEncryptor())
                {
                    byte[] rrbytes = transform.TransformFinalBlock(ksnZeroCounter, 0, ksnZeroCounter.Length);
                    // Right Register is first 8 bytes
                    byte[] rightRegister = new byte[8];
                    Array.Copy(rrbytes, rightRegister, 8);
                    return rightRegister;
                }
            }
        }

        static byte[] SetDataMask(byte[] key)
        {
            byte[] rgkey = new byte[DDMASK.Length];
            int i = 0;

            // key ^ DDMASK
            foreach (byte value in key)
            {
                rgkey[i] = (byte)(DDMASK[i] ^ value);
                i++;
            }

            // Append 8-MSB from the resulting masked array
            byte[] registerKey = new byte[DDMASK.Length];
            Array.Copy(rgkey, registerKey, rgkey.Length);

            //1234567890|1234567890|12345
            Debug.WriteLine($"MASKED KEY : {ConversionHelper.ByteArrayToHexString(registerKey)}");

            return registerKey;
        }

        static byte[] SetRegisterMask(byte[] key)
        {
            byte[] rgkey = new byte[RGMASK.Length];
            int i = 0;

            // key ^ RGMASK
            foreach (byte value in key)
            {
                rgkey[i] = (byte)(RGMASK[i] ^ value);
                i++;
            }

            // Append 8-MSB from the resulting masked array
            byte[] registerKey = new byte[RGMASK.Length];
            Array.Copy(rgkey, registerKey, rgkey.Length);

            //1234567890|1234567890|12345
            Debug.WriteLine($"MASKED KEY : {ConversionHelper.ByteArrayToHexString(registerKey)}");

            return registerKey;
        }

        static byte[] SetSessionRegisterMask(byte[] ksn, byte[] dataKey)
        {
            byte[] baseKSN = new byte[8];
            Array.Copy(ksn, 2, baseKSN, 0, 8);

            byte[] bKSN = new byte[10] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            int i = 0;
            foreach (byte value in baseKSN)
            {
                bKSN[i + 2] = (byte)(KSNZERO[i] & value);
                i++;
            }

            //1234567890|1234567890|12345
            Debug.WriteLine($"BASE KSN __: {ConversionHelper.ByteArrayToHexString(bKSN)}");

            // Append 8-MSB from the resulting masked array
            byte[] ssRegister = new byte[DDMASK.Length + 8];
            Array.Copy(bKSN, ssRegister, bKSN.Length);

            return ssRegister;
        }

        static byte[] GenerateDataRegister(byte[] key, byte[] ksn)
        {
            // break down key in two parts
            byte[] top8Value = new byte[key.Length / 2];
            byte[] bot8Value = new byte[key.Length / 2];

            Array.Copy(key, 0, top8Value, 0, key.Length / 2);
            Array.Copy(key, key.Length / 2, bot8Value, 0, key.Length / 2);

            byte[] regkey = new byte[key.Length / 2];
            int i = 0;

            // Bottom XOR value
            foreach (byte value in ksn)
            {
                regkey[i] = (byte)(bot8Value[i] ^ value);
                i++;
            }

            //Debug.WriteLine($"TOP-8 _____: {ConversionHelper.ByteArrayToHexString(top8Value)}");
            //Debug.WriteLine($"BOT-8 _____: {ConversionHelper.ByteArrayToHexString(regkey)}");

            // single-DES Encryption
            using (var des = new DESCryptoServiceProvider())
            {
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.None;
                des.Key = top8Value;

                using (var transform = des.CreateEncryptor())
                {
                    byte[] ssbytes = transform.TransformFinalBlock(regkey, 0, regkey.Length);
                    byte[] registerKey = new byte[ssbytes.Length];

                    i = 0;

                    // single-DES using bottom of 8 bytes of key XOR'd with KSN
                    foreach (byte value in ssbytes)
                    {
                        registerKey[i] = (byte)(bot8Value[i] ^ value);
                        i++;
                    }

                    return registerKey;
                }
            }
        }

        static byte[] EDE3KeyExpand(byte[] finalKey)
        {
            int expandedKeyLen = finalKey.Length + finalKey.Length / 2;
            byte[] expandedKey = new byte[expandedKeyLen];
            Array.Copy(finalKey, expandedKey, finalKey.Length);
            Array.Copy(finalKey, 0, expandedKey, finalKey.Length, finalKey.Length / 2);
            return expandedKey;
        }

        static byte[] FinalPermutationOnSessionKey(byte[] lReg, byte[] rReg)
        {
            byte[] rgkey = new byte[DDMASK.Length];
            int i = 0;

            // lReg ^ DDMASK
            foreach (byte value in lReg)
            {
                rgkey[i] = (byte)(DDMASK[i] ^ value);
                i++;
            }

            // rReg ^ DDMASK
            foreach (byte value in rReg)
            {
                rgkey[i] = (byte)(DDMASK[i] ^ value);
                i++;
            }


            // Append 8-MSB from the resulting masked array
            byte[] registerKey = new byte[DDMASK.Length];
            Array.Copy(rgkey, registerKey, rgkey.Length);

            //1234567890|1234567890|12345
            Debug.WriteLine($"FINAL KEY _: {ConversionHelper.ByteArrayToHexString(registerKey)}");

            return registerKey;
        }

        static byte [] SetDataKeyVariantKSN(byte[] ksn, int counterValue)
        {
            byte[] dataSessionKSN = new byte[ksn.Length];

            if (counterValue > 0)
            {
                Array.Copy(ksn, dataSessionKSN, ksn.Length);

                int i = 0;
                for (int shiftReg = 0x00100000; shiftReg > 0; shiftReg >>= 1, i++)
                {
                    if ((shiftReg & counterValue) > 0)
                    {
                        dataSessionKSN[5] |= (byte)((shiftReg >> 16) & 0x0000FF);
                        dataSessionKSN[6] |= (byte)((shiftReg >>  8) & 0x0000FF);
                        dataSessionKSN[7] |= (byte)((shiftReg >>  0) & 0x0000FF);
                    }
                }
            }
            else
            {
                Array.Copy(ksn, 2, dataSessionKSN, 0, ksn.Length - 2);
            }

            return dataSessionKSN;
        }

        static byte[] GenerateKey(byte[] key, byte[] ksn)
        {
            // generate register mask
            byte[] maskedKey = SetRegisterMask(key);

            byte[] registerKeys = new byte[RegisterSize];

            // LEFT REGISTER ENCRYPTION
            byte[] leftRegister = GenerateDataRegister(maskedKey, ksn);
            Array.Copy(leftRegister, registerKeys, leftRegister.Length);

            // RIGHT REGISTER ENCRYPTION
            byte[] rightRegister = GenerateDataRegister(key, ksn);
            Array.Copy(rightRegister, 0, registerKeys, rightRegister.Length, rightRegister.Length);

            //1234567890|1234567890|12345
            Debug.WriteLine($"IPEK_______: {ConversionHelper.ByteArrayToHexString(leftRegister)}-{ConversionHelper.ByteArrayToHexString(rightRegister)}");

            return registerKeys;
        }

        static byte[] CreateSessionKey(byte[] registerKeys, byte[] ksn)
        {
            try
            {
                // generate register mask
                byte[] maskedKey = SetDataMask(registerKeys);

                // generate left register
                //byte[] leftRegister = GenerateDataRegister(maskedKey, ksn);

                // generate right register
                //byte[] rightRegister = GenerateDataRegister(registerKeys, ksn);

                //1234567890|1234567890|12345
                //Debug.WriteLine($"SESS REGSTR: {ConversionHelper.ByteArrayToHexString(leftRegister)}-{ConversionHelper.ByteArrayToHexString(rightRegister)}");

                // Final Permutation
                //byte[] finalKey = FinalPermutationOnSessionKey(leftRegister, rightRegister);

                // TDES-encrypt the masked key in two parts, using itself as the key. This is a one-way function (OWF).
                // The leftmost 8 bytes are encrypted, then the rightmost 8 bytes are encrypted separately. In each case,
                // the key is the entire original 16-byte maskedPEK from the above step, expanded to 24 bytes per EDE3.

                // left half
                byte[] ede3Key = EDE3KeyExpand(maskedKey);

                //1234567890|1234567890|12345
                Debug.WriteLine($"PEK REDUCED: {ConversionHelper.ByteArrayToHexString(ede3Key)}");

                byte[] sessionKey = new byte[24];
                byte[] dataSessionKSN = SetDataKeyVariantKSN(ksn, 0);

                using (var tdes = new TripleDESCryptoServiceProvider())
                {
                    tdes.Mode = CipherMode.ECB;
                    tdes.Padding = PaddingMode.PKCS7;
                    tdes.Key = ede3Key;

                    // LEFT HALF
                    using (var transform = tdes.CreateEncryptor())
                    {
                        byte[] lHalf = new byte[8];
                        Array.Copy(maskedKey, lHalf, 8);
                        byte[] ssbytes = transform.TransformFinalBlock(lHalf, 0, lHalf.Length);
                        Array.Copy(ssbytes, sessionKey, 8);
                    }

                    // RIGHT HALF
                    using (var transform = tdes.CreateEncryptor())
                    {
                        byte[] rHalf = new byte[8];
                        Array.Copy(maskedKey, 8, rHalf, 0, 8);
                        byte[] ssbytes = transform.TransformFinalBlock(rHalf, 0, rHalf.Length);
                        Array.Copy(ssbytes, 0, sessionKey, 8, 8);

                        //1234567890|1234567890|12345
                        Debug.WriteLine($"CURRENT KEY: {ConversionHelper.ByteArrayToHexString(sessionKey)}");

                        // Add extended bytes to session key
                        Array.Copy(sessionKey, 0, sessionKey, 16, 8);

                        return sessionKey;
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"EXCEPTION: {e.Message}");
                return null;
            }
        }
        
        static byte[] GenerateIPEK(byte[] baseKSN)
        {
            byte[] registerKeys = new byte[RegisterSize];

            // LEFT REGISTER ENCRYPTION
            byte[] leftRegister = GenerateLeftRegister(baseKSN);
            Array.Copy(leftRegister, registerKeys, leftRegister.Length);

            // RIGHT REGISTER ENCRYPTION
            byte[] rightRegister = GenerateRightRegister(baseKSN);
            Array.Copy(rightRegister, 0, registerKeys, rightRegister.Length, rightRegister.Length);

            //1234567890|1234567890|12345
            Debug.WriteLine($"IPEK_______: {ConversionHelper.ByteArrayToHexString(leftRegister)}-{ConversionHelper.ByteArrayToHexString(rightRegister)}");

            return registerKeys;
        }

        public static byte[] DecryptData(byte[] ksn, string cipher)
        {
            byte[] finalBytes = null;

            List<int> totalPasses = GetTotalEncryptionPasses(ksn);

            // base IPEK
            byte[] iPEK = GenerateIPEK(ksn);

            // set KSN counter to 0
            byte[] ksnZeroCounter = SetKSNZeroCounter(ksn);

            // set BASE KSN
            byte[] baseKSN = SetDataKeyVariantKSN(ksnZeroCounter, 0);
            Debug.WriteLine($"BASE KSN __: {ConversionHelper.ByteArrayToHexString(baseKSN)}");

            foreach (int pass in totalPasses)
            {
                baseKSN = SetDataKeyVariantKSN(baseKSN, pass);

                //1234567890|1234567890|12345
                Debug.WriteLine($"ACTIVE KSN : {ConversionHelper.ByteArrayToHexString(baseKSN)}");

                iPEK = GenerateKey(iPEK, baseKSN);

                //byte[] registerKeys = new byte[RegisterSize];

                // LEFT REGISTER ENCRYPTION
                //byte[] leftRegister = GenerateLeftRegister(baseKSN);
                //Array.Copy(leftRegister, registerKeys, leftRegister.Length);

                // RIGHT REGISTER ENCRYPTION
                //byte[] rightRegister = GenerateRightRegister(baseKSN);
                //Array.Copy(rightRegister, 0, registerKeys, rightRegister.Length, rightRegister.Length);

                //1234567890|1234567890|12345
                //Debug.WriteLine($"IPEK_______: {ConversionHelper.ByteArrayToHexString(leftRegister)}-{ConversionHelper.ByteArrayToHexString(rightRegister)}");

                //byte[] sessionKey = CreateSessionKey(registerKeys, baseKSN);

                //1234567890|1234567890|12345
                //Debug.WriteLine($"SESSION KEY: {ConversionHelper.ByteArrayToHexString(sessionKey)}");

                /*using (var tdes = new TripleDESCryptoServiceProvider())
                {
                    tdes.Mode = CipherMode.ECB;
                    tdes.Padding = PaddingMode.PKCS7;
                    tdes.Key = sessionKey;

                    using (var transform = tdes.CreateEncryptor())
                    {
                        byte[] textBytes = UTF8Encoding.UTF8.GetBytes(cipher);
                        finalBytes = transform.TransformFinalBlock(textBytes, 0, textBytes.Length);
                    }
                }*/
            }

            byte[] sessionKey = CreateSessionKey(iPEK, baseKSN);

            //1234567890|1234567890|12345
            Debug.WriteLine($"DECRYPT KEY: {ConversionHelper.ByteArrayToHexString(sessionKey)}");

            using (var tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Mode = CipherMode.CBC;
                tdes.Padding = PaddingMode.None;
                tdes.Key = sessionKey;
                tdes.IV = new byte[8];

                using (var transform = tdes.CreateDecryptor())
                {
                    byte[] textBytes = ConversionHelper.HexToByteArray(cipher);
                    finalBytes = transform.TransformFinalBlock(textBytes, 0, textBytes.Length);
                }
            }

            //return Convert.ToBase64String(finalBytes, 0, finalBytes.Length);
            return finalBytes;
        }
    }
}
