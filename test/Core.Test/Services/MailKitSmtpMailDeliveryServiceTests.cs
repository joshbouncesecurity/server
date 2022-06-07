using System;
using Bit.Core.Services;
using Bit.Core.Settings;
using Xunit;

namespace Bit.Core.Test.Services
{
    public class MailKitSmtpMailDeliveryServiceTests
    {
        private readonly MailKitSmtpMailDeliveryService _sut;

        private readonly GlobalSettings _globalSettings;

        public MailKitSmtpMailDeliveryServiceTests()
        {
            _globalSettings = new GlobalSettings();

            _globalSettings.Mail.Smtp.Host = "unittests.example.com";
            _globalSettings.Mail.ReplyToEmail = "noreply@unittests.example.com";

            _sut = new MailKitSmtpMailDeliveryService(
                _globalSettings
            );
        }

        // Remove this test when we add actual tests. It only proves that
        // we've properly constructed the system under test.
        [Fact]
        public void ServiceExists()
        {
            Assert.NotNull(_sut);
        }
    }
}
