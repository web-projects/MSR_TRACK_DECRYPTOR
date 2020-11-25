using DecryptTrack1Data.Decryptor;
using DecryptTrack1Data.Helpers;
using System;
using System.Diagnostics;

namespace DecryptTrack1Data
{
    /// <summary>
    ///
    /// BDK: 0123456789ABCDEFFEDCBA9876543210
    /// KEY LEN: 32 BYTES
    /// 
    /// DFDF10: ENCRYPTED DATA
    /// dfdf10-50-87a73106f57b8fbdd383a257ed8c713a62bfae83e9b0d202c50fe1f7da8739338c768ba61506c1d3404191c7c8c3016929a0cce6621b95191d5a006382605fb0c17963725b548abc37ffda146e0429e7
    /// KEY LEN: 80 bytes
    /// 
    /// DFDF11: KSN
    /// dfdf11-0a-ffff9876543211000620
    /// KEY LEN: 10 bytes
    /// 
    /// DFDF12: IV DATA
    /// dfdf12-08-a79ddd0ff736b32b
    /// KEY LEN: 8 bytes
    /// 
    /// </summary>
    class Program
    {
        // TEST: FFFF9876543211000620
        public static readonly byte[] KSN = new byte[] { 0xff, 0xff, 0x98, 0x76, 0x54, 0x32, 0x11, 0x00, 0x06, 0x20 };
        // TEST: FFFF9876543210E00008
        //public static readonly byte[] KSN = new byte[] { 0xff, 0xff, 0x98, 0x76, 0x54, 0x32, 0x10, 0xE0, 0x00, 0x08 };

        // ENCRYPTED TRACK DATA
        public static readonly string DATA = "87A73106F57B8FBDD383A257ED8C713A62BFAE83E9B0D202C50FE1F7DA8739338C768BA61506C1D3404191C7C8C3016929A0CCE6621B95191D5A006382605FB0C17963725B548ABC37FFDA146E0429E7";

        static void Main(string[] args)
        {
            try
            {
                TrackDataDecryptor decryptor = new TrackDataDecryptor();
                byte[] trackData = decryptor.DecryptData(KSN, DATA);
                string convertedTrack = ConversionHelper.ByteArrayToHexString(trackData);

                //1234567890|1234567890|12345
                Debug.WriteLine($"OUTPUT ____: {convertedTrack}");

                Console.WriteLine($"OUTPUT: [{convertedTrack}]");
            }
            catch (Exception e)
            {
                Console.WriteLine($"EXCEPTION: {e.Message}");
            }
        }
    }
}
