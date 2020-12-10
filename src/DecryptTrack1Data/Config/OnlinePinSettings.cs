using System;
using System.Collections.Generic;

namespace DecryptTrack1Data.Config
{
    [Serializable]
    public class OnlinePinSettings
    {
        public List<string> OnlinePinGroup { get; internal set; } = new List<string>();
    }
}
