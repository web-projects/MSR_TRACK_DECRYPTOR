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
        public void DecryptData_ShouldDecryptTrackData_WhenCalled(string ksn, string encryptedTrack, string decryptedTrack)
        {
            byte[] expectedValue = ConversionHelper.HexToByteArray(decryptedTrack);

            byte[] actualValue = subject.DecryptData(ksn, encryptedTrack);

            Assert.Equal(expectedValue, actualValue);
        }

        [Theory]
        [InlineData("DFDB06283B3337393630353137373131313131383D3235313231303130373130383036393930303030303F33DFDB053525423337393630353137373131313131385E49534F2F414D455854455354202020205E323531323130313037313038303639393F3F800000", "379605177111118", "ISO/AMEXTEST    ", "071080699")]
        //[InlineData("23B281E8E126E1EA3630353137373131313131383D3235313231303130373130383036393930303030303F33DFDB053525423337393630353137373131313131385E49534F2F414D455854455354202020205E323531323130313037313038303639393F3F800000", "", "ISO/AMEXTEST    ", "071080699")]
        //[InlineData("2542343831353838313030323836313839365E444F452F4C204A4F484E2020202020202020202020205E3232313231303233353638353820202020202030303939383030303030303F", "", "DOE/L JOHN            ", "")]
        //[InlineData("7846D845D274861F32343138303030313233343536335E4644435320544553542043415244202F4D4153544552434152445E32353132313031303030313131313132333435363738393031323F438000", "", "FDCS TEST CARD /MASTERCARD", "")]
        //[InlineData("19143D2F3491E8AA3935333139323335313030343D323530323135303331323334353F3BDFDB053E254233373339203533313932332035313030345E414D45582054455354204341524420414E5349202020202020205E323030383130303831323334353F5D8000", "", "AMEX TEST CARD ANSI       ", "")]
        public void RetrieveTrackData_ShouldProcessTrackData_WhenCalled(string decryptedTrack, string panData, string cardholderName, string discretionaryData)
        {
            byte[] trackInformation = ConversionHelper.HexToByteArray(decryptedTrack);

            MSRTrackData trackData = subject.RetrieveTrackData(trackInformation);

            Assert.NotNull(trackData.PANData);
            Assert.NotNull(trackData.Name);
            Assert.NotNull(trackData.ExpirationDate);
            Assert.Equal(panData, trackData.PANData); 
            Assert.Equal(cardholderName, trackData.Name);
            Assert.Equal(discretionaryData, trackData.DiscretionaryData);
        }


        [Theory]
        [InlineData("DFDB05472542353432343138303030303030353535305E524150494420434F4E4E45435420544553542F4D435E323531323130313130303031313131413132333435363738393031323F22DFDB06283B353432343138303030303030353535303D32353132313031313030303030313233343536373F3780", "5424180000005550", "RAPID CONNECT TEST/MC", "2512", "10001111A123456789012")]
        [InlineData("DFDB05472542343736313533303030313131353535365E46444D53205445535420434152442F564953415E3235313231303135343332313030303030303030303030303030303135303F45DFDB06283B343736313533303030313131353535363D32353132313031313030303031323334353637383F3480", "4761530001115556", "FDMS TEST CARD/VISA", "2512", "54321000000000000000150")]
        [InlineData("DFDB0542254233363138353937333332353833375E46444D5354455354434152442F44494E4552535E3235313231303135343332313030303030303030303030303135303F53DFDB06263B33363138353937333332353833373D32353132313031313030303031323334353637383F38", "36185973325837", "FDMSTESTCARD/DINERS", "2512", "54321000000000000150")]
        public void RetrieveSREDTrackData_ShouldProcessTrackData_WhenCalled(string decryptedTrack, string panData, string cardholderName, string expiry, string discretionaryData)
        {
            byte[] trackInformation = ConversionHelper.HexToByteArray(decryptedTrack);

            MSRTrackData trackData = subject.RetrieveSREDTrackData(trackInformation);

            Assert.NotNull(trackData.PANData);
            Assert.NotNull(trackData.Name);
            Assert.NotNull(trackData.ExpirationDate);
            Assert.Equal(panData, trackData.PANData);
            Assert.Equal(cardholderName, trackData.Name);
            Assert.Equal(expiry, trackData.ExpirationDate);
            Assert.Equal(discretionaryData, trackData.DiscretionaryData);
        }
    }
}