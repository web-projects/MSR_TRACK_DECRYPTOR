using System;

namespace DecryptTrack1Data.Config
{
    [Serializable]
    public class DeviceSection
    {
        public OnlinePinSettings onlinePinSettings { get; internal set; } = new OnlinePinSettings();
    }
}
