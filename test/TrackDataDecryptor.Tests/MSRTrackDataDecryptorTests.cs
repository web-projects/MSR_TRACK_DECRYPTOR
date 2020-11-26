using DecryptTrack1Data.Decryptor;
using DecryptTrack1Data.Helpers;
using System.Collections.Generic;
using TestHelper;
using Xunit;
using ConversionHelper = TestHelper.ConversionHelper;

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
        [InlineData("FFFF9876543211000620", 3)]
        [InlineData("FFFF9876543211000636", 6)]
        [InlineData("FFFF9876543211000637", 7)]
        public void GetTotalEncryptionPasses_ShouldReturnNumberOfPasses_WhenCalled(string ksn, int expectedValue)
        {
            byte[] initialKSN = ConversionHelper.HexToByteArray(ksn);

            Helper.CallPrivateMethod("GetTotalEncryptionPasses", subject, out List<int> passList, new object[] { initialKSN });

            Assert.Equal(expectedValue, passList.Count);
        }

        [Theory]
        [InlineData("FFFF9876543211000620", "87A73106F57B8FBDD383A257ED8C713A62BFAE83E9B0D202C50FE1F7DA8739338C768BA61506C1D3404191C7C8C3016929A0CCE6621B95191D5A006382605FB0C17963725B548ABC37FFDA146E0429E7", "7846D845D274861F32343138303030313233343536335E4644435320544553542043415244202F4D4153544552434152445E32353132313031303030313131313132333435363738393031323F438000")]
        [InlineData("FFFF9876543211000637", "4B989D098BDFB546440317F5CDBF51D2E28E70AAD885FC0B95F8EFCD97E8D832284B4EB8DD03C792", "E00DD987655115BB313030303939333032363930393D3230313231303130303030303F3980000000")]
        //[InlineData("", "", "")]
        public void DecryptData_ShouldDecryptTrackData_WhenCalled(string ksn, string encryptedTrack, string decryptedTrack)
        {
            byte[] expectedValue = ConversionHelper.HexToByteArray(decryptedTrack);

            byte[] actualValue = subject.DecryptData(ksn, encryptedTrack);

            Assert.Equal(expectedValue, actualValue);
        }

        [Theory]
        [InlineData("7846D845D274861F32343138303030313233343536335E4644435320544553542043415244202F4D4153544552434152445E32353132313031303030313131313132333435363738393031323F438000", "FDCS TEST CARD /MASTERCARD", "")]
        [InlineData("19143D2F3491E8AA3935333139323335313030343D323530323135303331323334353F3BDFDB053E254233373339203533313932332035313030345E414D45582054455354204341524420414E5349202020202020205E323030383130303831323334353F5D8000", "AMEX TEST CARD ANSI       ", "")]
        public void RetrieveTrackData_ShouldProcessTrackData_WhenCalled(string decryptedTrack, string cardholderName, string discretionaryData)
        {
            byte[] trackInformation = ConversionHelper.HexToByteArray(decryptedTrack);

            MSRTrackData trackData = subject.RetrieveTrackData(trackInformation);

            Assert.NotNull(trackData.PANData);
            Assert.NotNull(trackData.Name);
            Assert.NotNull(trackData.ExpirationDate);
            Assert.Equal(cardholderName, trackData.Name);
            Assert.Equal(discretionaryData, trackData.DiscretionaryData);
        }
    }
}