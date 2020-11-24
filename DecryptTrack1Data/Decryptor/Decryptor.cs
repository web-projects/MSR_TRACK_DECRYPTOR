using DecryptTrack1Data.Helpers;
using System;
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
        static readonly byte[] RRMASK = new byte[] { 0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00, 0x00 };
        static readonly byte[] DDMASK = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00 };
        static readonly byte[] FFMAXK = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF }; 

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

            foreach (byte value in BDKMASK)
            {
                rrksn[i] = (byte)(RRMASK[i] ^ value);
                i++;
            }

            // Append 8-MSB from the resulting masked array
            byte[] rightRegister = new byte[BDKMASK.Length + 8];
            Array.Copy(rrksn, rightRegister, rrksn.Length);
            Array.Copy(rrksn, 0, rightRegister, rrksn.Length, 8);

            return rightRegister;
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

        static byte[] SetSessionRegisterMask(byte[] ksn, byte[] dataKey)
        {
            byte[] ssKey = new byte[DDMASK.Length];
            int i = 0;

            byte[] baseKSN = new byte[8];
            Array.Copy(ksn, 2, baseKSN, 0, 8);

            byte[] bKSN = new byte[10] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            foreach (byte value in baseKSN)
            {
                bKSN[i+2] = (byte)(KSNZERO[i] & value);
                i++;
            }

            //1234567890|1234567890|12345
            /*Debug.WriteLine($"BASE KSN __: {ConversionHelper.ByteArrayToHexString(bKSN)}");

            foreach (byte value in DDMASK)
            {
                ssKey[i] = (byte)(dataKey[i] & value);
                i++;
            }

            // Append 8-MSB from the resulting masked array
            byte[] ssRegister = new byte[DDMASK.Length + 8];
            Array.Copy(ssKey, ssRegister, ssKey.Length);
            Array.Copy(ssKey, 0, ssRegister, ssKey.Length, 8);*/

            byte[] ssRegister = new byte[bKSN.Length];
            Array.Copy(bKSN, ssRegister, bKSN.Length);

            //1234567890|1234567890|12345
            Debug.WriteLine($"SESSION KEY: {ConversionHelper.ByteArrayToHexString(ssRegister)}");

            return ssRegister;
        }

        static byte[] CreateSessionKey(byte[] registerKeys, byte[] ksn)
        {
            using (var tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.PKCS7;
                tdes.Key = SetSessionRegisterMask(ksn, registerKeys);

                using (var transform = tdes.CreateEncryptor())
                {
                    byte[] ssbytes = transform.TransformFinalBlock(registerKeys, 0, registerKeys.Length);
                    // Right Register is first 8 bytes
                    byte[] sessionKey = new byte[8];
                    Array.Copy(ssbytes, sessionKey, 8);
                    return sessionKey;
                }
            }
        }

        public static string DecryptData(byte[] ksn, string cipher)
        {
            // set KSN counter to 0
            byte[] ksnZeroCounter = SetKSNZeroCounter(ksn);
            byte[] registerKeys = new byte[RegisterSize];

            // LEFT REGISTER ENCRYPTION
            byte[] leftRegister = GenerateLeftRegister(ksnZeroCounter);
            Array.Copy(leftRegister, registerKeys, leftRegister.Length);

            // RIGHT REGISTER ENCRYPTION
            byte[] rightRegister = GenerateRightRegister(ksnZeroCounter);
            Array.Copy(rightRegister, 0, registerKeys, rightRegister.Length, rightRegister.Length);

            //1234567890|1234567890|12345
            Debug.WriteLine($"IPEK_______: {ConversionHelper.ByteArrayToHexString(leftRegister)}-{ConversionHelper.ByteArrayToHexString(rightRegister)}");

            byte[] sessionKey = CreateSessionKey(registerKeys, ksn);

            using (var tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Mode = CipherMode.ECB;
                tdes.Padding = PaddingMode.PKCS7;
                tdes.Key = registerKeys;

                using (var transform = tdes.CreateEncryptor())
                {
                    byte[] textBytes = UTF8Encoding.UTF8.GetBytes(cipher);
                    byte[] bytes = transform.TransformFinalBlock(textBytes, 0, textBytes.Length);
                    return Convert.ToBase64String(bytes, 0, bytes.Length);
                }
            }
        }
    }
}
