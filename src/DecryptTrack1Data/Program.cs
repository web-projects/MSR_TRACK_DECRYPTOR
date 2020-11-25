using DecryptTrack1Data.Decryptor;
using DecryptTrack1Data.Helpers;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;

namespace DecryptTrack1Data
{
    /// <summary>
    /// 
    /// Program to validate MSR Track decryptor for a given swipe transaction
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
        // Actual Transactions
        public static List<TrackPayload> trackPayload = new List<TrackPayload>()
        {
            // TEST: FFFF9876543211000620
            new TrackPayload()
            {
                KSN = "FFFF9876543211000620",
                EncryptedData = "87A73106F57B8FBDD383A257ED8C713A62BFAE83E9B0D202C50FE1F7DA8739338C768BA61506C1D3404191C7C8C3016929A0CCE6621B95191D5A006382605FB0C17963725B548ABC37FFDA146E0429E7",
                DecryptedData = "7846D845D274861F32343138303030313233343536335E4644435320544553542043415244202F4D4153544552434152445E32353132313031303030313131313132333435363738393031323F438000"
            }
        };

        static void Main(string[] args)
        {
            try
            {
                foreach (var item in trackPayload)
                {
                    TrackDataDecryptor decryptor = new TrackDataDecryptor();

                    byte[] KSN = ConversionHelper.HexToByteArray(item.KSN);

                    // decryptor in action
                    byte[] trackInformation = decryptor.DecryptData(KSN, item.EncryptedData);
                    
                    string decryptedTrack = ConversionHelper.ByteArrayToHexString(trackInformation);

                    //1234567890|1234567890|12345
                    Debug.WriteLine($"OUTPUT ____: {decryptedTrack}");
                    Console.WriteLine($"OUTPUT : [{decryptedTrack}]");

                    byte[] expectedValue = ConversionHelper.HexToByteArray(item.DecryptedData);
                    bool result = StructuralComparisons.StructuralEqualityComparer.Equals(expectedValue, trackInformation);
                    Console.WriteLine($"EQUAL  : [{result}]");

                    TrackData trackData = decryptor.RetrieveTrackData(trackInformation);
                    Console.WriteLine($"CHOLDER: [{trackData.Name}]");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"EXCEPTION: {e.Message}");
            }
        }
    }
}
