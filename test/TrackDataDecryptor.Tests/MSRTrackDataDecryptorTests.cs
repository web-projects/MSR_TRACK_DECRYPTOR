using DecryptTrack1Data.Decryptor;
using DecryptTrack1Data.Helpers;
using TestHelper;
using Xunit;

namespace MSRDecryptTrack1Data.Tests
{
    public class MSRTrackDataDecryptorTests
    {
        readonly MSRTrackDataDecryptor subject;

        public MSRTrackDataDecryptorTests()
        {
            subject = new MSRTrackDataDecryptor();
        }

        [Theory]
        [InlineData("FFFF9876543211000620", "87A73106F57B8FBDD383A257ED8C713A62BFAE83E9B0D202C50FE1F7DA8739338C768BA61506C1D3404191C7C8C3016929A0CCE6621B95191D5A006382605FB0C17963725B548ABC37FFDA146E0429E7", "7846D845D274861F32343138303030313233343536335E4644435320544553542043415244202F4D4153544552434152445E32353132313031303030313131313132333435363738393031323F438000")]
        public void DecryptData_ShouldDecryptTrackData_WhenCalled(string ksn, string encryptedTrack, string decryptedTrack)
        {
            byte[] expectedValue = Helper.HexToByteArray(decryptedTrack);

            byte[] actualValue = subject.DecryptData(ksn, encryptedTrack);


            Assert.Equal(expectedValue, actualValue);
        }

        [Theory]
        [InlineData("7846D845D274861F32343138303030313233343536335E4644435320544553542043415244202F4D4153544552434152445E32353132313031303030313131313132333435363738393031323F438000", "")]
        public void RetrieveTrackData_ShouldProcessTrackData_WhenCalled(string decryptedTrack, string discretionaryData)
        {
            byte[] trackInformation = Helper.HexToByteArray(decryptedTrack);

            MSRTrackData trackData = subject.RetrieveTrackData(trackInformation);

            Assert.NotNull(trackData.PANData);
            Assert.NotNull(trackData.Name);
            Assert.NotNull(trackData.ExpirationDate);
            Assert.Equal(discretionaryData, trackData.DiscretionaryData);
        }
    }
}