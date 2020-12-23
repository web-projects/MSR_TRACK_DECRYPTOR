using DecryptTrack1Data.Decryptor;
using DecryptTrack1Data.Helpers;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;

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
        public static List<MSRTrackPayload> trackPayload = new List<MSRTrackPayload>()
        {
            // TEST: FFFF9876543211000620
            new MSRTrackPayload()
            {
                KSN = "FFFF9876543211000620",
                EncryptedData = "87A73106F57B8FBDD383A257ED8C713A62BFAE83E9B0D202C50FE1F7DA8739338C768BA61506C1D3404191C7C8C3016929A0CCE6621B95191D5A006382605FB0C17963725B548ABC37FFDA146E0429E7",
                DecryptedData = "7846D845D274861F32343138303030313233343536335E4644435320544553542043415244202F4D4153544552434152445E32353132313031303030313131313132333435363738393031323F438000"
            },
            new MSRTrackPayload()
            {
                KSN = "FFFF987654321100063D",
                EncryptedData = "7D507A729FB58FE67D6E5C829752518A2E3FEE081076E52AAB1B31916AD9EF3A33DFB5930410B6D4240F0E2065EEAA6C93D57C718F1A03A49CACC90693EBE05D311C7638B44A24271C0A9AAF7A3556580767B075FEEC7511B025A5CB644EF3605D6294F81FF47D3",
                DecryptedData = "19143D2F3491E8AA3935333139323335313030343D323530323135303331323334353F3BDFDB053E254233373339203533313932332035313030345E414D45582054455354204341524420414E5349202020202020205E323030383130303831323334353F5D8000"
            }
        };

        static void Main(string[] args)
        {
            Console.WriteLine($"\r\n==========================================================================================");
            Console.WriteLine($"{Assembly.GetEntryAssembly().GetName().Name} - Version {Assembly.GetEntryAssembly().GetName().Version}");
            Console.WriteLine($"==========================================================================================\r\n");

            //InternalTesting();
            ConfigurationLoad();
        }

        static void ConfigurationLoad()
        {
            // Get appsettings.json config.
            IConfiguration configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddEnvironmentVariables()
                .Build();


            var onlinePin = configuration.GetSection("OnlinePinGroup:OnlinePin")
                    .GetChildren()
                    .ToList()
                    .Select(x => new
                    {
                        onlinePinKsn = x.GetValue<string>("KSN"),
                        onlinePinData = x.GetValue<string>("EncryptedData")
                    });

            int index = 2;

            if (onlinePin.Count() > index)
            {
                string onlinePinKsn = onlinePin.ElementAt(index).onlinePinKsn;
                string onlinePinData = onlinePin.ElementAt(index).onlinePinData;

                try
                {
                    MSRTrackDataDecryptor decryptor = new MSRTrackDataDecryptor();

                    Console.WriteLine($"KSN      : {onlinePinKsn}");
                    Console.WriteLine($"DATA     : {onlinePinData}");

                    // decryptor in action
                    byte[] trackInformation = decryptor.DecryptData(onlinePinKsn, onlinePinData);

                    string decryptedTrack = ConversionHelper.ByteArrayToHexString(trackInformation);

                    //1234567890|1234567890|12345
                    Console.WriteLine($"OUTPUT   : {decryptedTrack}");
                    Debug.WriteLine($"OUTPUT ____: {decryptedTrack}");

                    //MSRTrackData trackInfo = decryptor.RetrieveAdditionalData(trackInformation);
                    MSRTrackData trackInfo = decryptor.RetrieveTrackData(trackInformation);

                    string expirationDate = "";

                    if (trackInfo.ExpirationDate.Length >= 4)
                        expirationDate = trackInfo.ExpirationDate.Substring(0, 2) + "/" + trackInfo.ExpirationDate.Substring(2, 2);

                    //1234567890|1234567890|12345
                    Debug.WriteLine($"PAN DATA     : {trackInfo.PANData}");
                    Debug.WriteLine($"EXPIR (YY/MM): {expirationDate}");
                    Debug.WriteLine($"SERVICE CODE : {trackInfo.ServiceCode}");
                    Debug.WriteLine($"DISCRETIONARY: {trackInfo.DiscretionaryData}");

                    Console.WriteLine($"EXPIRATE : {trackInfo.ExpirationDate}");
                    Console.WriteLine($"SERV CODE: {trackInfo.ServiceCode}");

                    //byte[] expectedValue = ConversionHelper.HexToByteArray(item.DecryptedData);
                    //bool result = StructuralComparisons.StructuralEqualityComparer.Equals(expectedValue, trackInformation);
                    //Console.WriteLine($"EQUAL  : [{result}]");

                    //MSRTrackData trackData = decryptor.RetrieveTrackData(trackInformation);
                    //Console.WriteLine($"CHOLDER: [{trackData.Name}]");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"EXCEPTION: {e.Message}");
                }
            }
        }

        static void InternalTesting()
        {
            try
            {
                foreach (var item in trackPayload)
                {
                    MSRTrackDataDecryptor decryptor = new MSRTrackDataDecryptor();

                    // decryptor in action
                    byte[] trackInformation = decryptor.DecryptData(item.KSN, item.EncryptedData);

                    string decryptedTrack = ConversionHelper.ByteArrayToHexString(trackInformation);

                    //1234567890|1234567890|12345
                    Debug.WriteLine($"OUTPUT ____: {decryptedTrack}");
                    Console.WriteLine($"OUTPUT : [{decryptedTrack}]");

                    byte[] expectedValue = ConversionHelper.HexToByteArray(item.DecryptedData);
                    bool result = StructuralComparisons.StructuralEqualityComparer.Equals(expectedValue, trackInformation);
                    Console.WriteLine($"EQUAL  : [{result}]");

                    MSRTrackData trackData = decryptor.RetrieveTrackData(trackInformation);
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
