using DecryptTrack1Data.Helpers;
using System;

namespace DecryptTrack1Data.Decryptor
{
    public interface ITrackDataDecryptor : IDisposable
    {
        byte[] DecryptData(byte[] ksn, string cipher);
        TrackData RetrieveTrackData(byte[] trackInformation);
    }
}
