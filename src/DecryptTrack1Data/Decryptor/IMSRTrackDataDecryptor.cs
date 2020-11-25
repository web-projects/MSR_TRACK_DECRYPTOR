using DecryptTrack1Data.Helpers;
using System;

namespace DecryptTrack1Data.Decryptor
{
    public interface IMSRTrackDataDecryptor : IDisposable
    {
        byte[] DecryptData(string initialKSN, string cipher);
        MSRTrackData RetrieveTrackData(byte[] trackInformation);
    }
}
