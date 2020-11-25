using System;

namespace DecryptTrack1Data.Decryptor
{
    public interface ITrackDataDecryptor : IDisposable
    {
        byte[] DecryptData(byte[] ksn, string cipher);
    }
}
