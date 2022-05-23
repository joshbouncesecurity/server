using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Bit.Core.Context;
using Bit.Core.Entities;
using Bit.Core.Enums;
using Bit.Core.Models;
using Bit.Core.Models.Api.Request.Accounts;
using Bit.Core.Models.Business;
using Bit.Core.Repositories;
using Bit.Core.Services;
using Bit.Core.Utilities;
using Bit.IntegrationTestCommon.Factories;
using Bit.Test.Common.AutoFixture.Attributes;
using Bit.Test.Common.Helpers;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using Xunit;

namespace Bit.Identity.IntegrationTest.Endpoints
{
    public class IdentityServerTests : IClassFixture<IdentityApplicationFactory>
    {
        private const int SecondsInMinute = 60;
        private const int MinutesInHour = 60;
        private const int SecondsInHour = SecondsInMinute * MinutesInHour;
        private readonly IdentityApplicationFactory _factory;

        public IdentityServerTests(IdentityApplicationFactory factory)
        {
            _factory = factory;
        }

        [Fact]
        public async Task WellKnownEndpoint_Success()
        {
            var context = await _factory.Server.GetAsync("/.well-known/openid-configuration");

            using var body = await AssertHelper.AssertResponseTypeIs<JsonDocument>(context);
            var endpointRoot = body.RootElement;

            // WARNING: Edits to this file should NOT just be made to "get the test to work" they should be made when intentional 
            // changes were made to this endpoint and proper testing will take place to ensure clients are backwards compatible
            // or loss of functionality is properly noted.
            await using var fs = File.OpenRead("openid-configuration.json");
            using var knownConfiguration = await JsonSerializer.DeserializeAsync<JsonDocument>(fs);
            var knownConfigurationRoot = knownConfiguration.RootElement;

            AssertHelper.AssertEqualJson(endpointRoot, knownConfigurationRoot);
        }

        [Fact]
        public async Task TokenEndpoint_BadClientId_Fails()
        {
            var context = await _factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "client_id", "__z__not_real" }
            }));

            Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
            await AssertInvalidClient(context);
        }

        [Fact]
        public async Task TokenEndpoint_GrantTypePassword_Success()
        {
            var deviceId = "92b9d953-b9b6-4eaf-9d3e-11d57144dfeb";
            var username = "test+tokenpassword@email.com";

            await _factory.RegisterAsync(new RegisterRequestModel
            {
                Email = username,
                MasterPasswordHash = "master_password_hash"
            });

            var context = await _factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "scope", "api offline_access" },
                { "client_id", "web" },
                { "deviceType", DeviceTypeAsString(DeviceType.FirefoxBrowser) },
                { "deviceIdentifier", deviceId },
                { "deviceName", "firefox" },
                { "grant_type", "password" },
                { "username", username },
                { "password", "master_password_hash" },
            }), context => context.Request.Headers.Add("Auth-Email", CoreHelpers.Base64UrlEncodeString(username)));

            using var body = await AssertDefaultTokenBodyAsync(context);
            var root = body.RootElement;
            AssertRefreshTokenExists(root);
            AssertHelper.AssertJsonProperty(root, "ForcePasswordReset", JsonValueKind.False);
            AssertHelper.AssertJsonProperty(root, "ResetMasterPassword", JsonValueKind.False);
            var kdf = AssertHelper.AssertJsonProperty(root, "Kdf", JsonValueKind.Number).GetInt32();
            Assert.Equal(0, kdf);
            var kdfIterations = AssertHelper.AssertJsonProperty(root, "KdfIterations", JsonValueKind.Number).GetInt32();
            Assert.Equal(5000, kdfIterations);
        }

        [Fact]
        public async Task TokenEndpoint_GrantTypePassword_NoAuthEmailHeader_Fails()
        {
            var deviceId = "92b9d953-b9b6-4eaf-9d3e-11d57144dfeb";
            var username = "test+noauthemailheader@email.com";

            await _factory.RegisterAsync(new RegisterRequestModel
            {
                Email = username,
                MasterPasswordHash = "master_password_hash",
            });

            var context = await _factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "scope", "api offline_access" },
                { "client_id", "web" },
                { "deviceType", DeviceTypeAsString(DeviceType.FirefoxBrowser) },
                { "deviceIdentifier", deviceId },
                { "deviceName", "firefox" },
                { "grant_type", "password" },
                { "username", username },
                { "password", "master_password_hash" },
            }));

            Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);

            var body = await AssertHelper.AssertResponseTypeIs<JsonDocument>(context);
            var root = body.RootElement;

            var error = AssertHelper.AssertJsonProperty(root, "error", JsonValueKind.String).GetString();
            Assert.Equal("invalid_grant", error);
            AssertHelper.AssertJsonProperty(root, "error_description", JsonValueKind.String);
        }

        [Fact]
        public async Task TokenEndpoint_GrantTypePassword_InvalidBase64AuthEmailHeader_Fails()
        {
            var deviceId = "92b9d953-b9b6-4eaf-9d3e-11d57144dfeb";
            var username = "test+badauthheader@email.com";

            await _factory.RegisterAsync(new RegisterRequestModel
            {
                Email = username,
                MasterPasswordHash = "master_password_hash",
            });

            var context = await _factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "scope", "api offline_access" },
                { "client_id", "web" },
                { "deviceType", DeviceTypeAsString(DeviceType.FirefoxBrowser) },
                { "deviceIdentifier", deviceId },
                { "deviceName", "firefox" },
                { "grant_type", "password" },
                { "username", username },
                { "password", "master_password_hash" },
            }), context => context.Request.Headers.Add("Auth-Email", "bad_value"));

            Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);

            var body = await AssertHelper.AssertResponseTypeIs<JsonDocument>(context);
            var root = body.RootElement;

            var error = AssertHelper.AssertJsonProperty(root, "error", JsonValueKind.String).GetString();
            Assert.Equal("invalid_grant", error);
            AssertHelper.AssertJsonProperty(root, "error_description", JsonValueKind.String);
        }

        [Fact]
        public async Task TokenEndpoint_GrantTypePassword_WrongAuthEmailHeader_Fails()
        {
            var deviceId = "92b9d953-b9b6-4eaf-9d3e-11d57144dfeb";
            var username = "test+badauthheader@email.com";

            await _factory.RegisterAsync(new RegisterRequestModel
            {
                Email = username,
                MasterPasswordHash = "master_password_hash",
            });

            var context = await _factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "scope", "api offline_access" },
                { "client_id", "web" },
                { "deviceType", DeviceTypeAsString(DeviceType.FirefoxBrowser) },
                { "deviceIdentifier", deviceId },
                { "deviceName", "firefox" },
                { "grant_type", "password" },
                { "username", username },
                { "password", "master_password_hash" },
            }), context => context.Request.Headers.Add("Auth-Email", CoreHelpers.Base64UrlEncodeString("bad_value")));

            Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);

            var body = await AssertHelper.AssertResponseTypeIs<JsonDocument>(context);
            var root = body.RootElement;

            var error = AssertHelper.AssertJsonProperty(root, "error", JsonValueKind.String).GetString();
            Assert.Equal("invalid_grant", error);
            AssertHelper.AssertJsonProperty(root, "error_description", JsonValueKind.String);
        }

        [Fact]
        public async Task TokenEndpoint_GrantTypePassword_Desktop_Success()
        {
            var deviceId = "1499f63c-fcad-4f32-bc3c-24334dc5da30";
            var username = "test+desktop@email.com";

            await _factory.RegisterAsync(new RegisterRequestModel
            {
                Email = username,
                MasterPasswordHash = "master_password_hash"
            });

            var context = await _factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "scope", "api offline_access" },
                { "client_id", "desktop" },
                // { "deviceType", DeviceTypeAsString(DeviceType.LinuxDesktop) },
                { "grant_type", "password" },
                { "username", username },
                { "password", "master_password_hash" },
            }), context => context.Request.Headers.Add("Auth-Email", CoreHelpers.Base64UrlEncodeString(username)));

            var responseBody = await context.ReadBodyAsStringAsync();

        }

        [Fact]
        public async Task TokenEndpoint_GrantTypeRefreshToken_Success()
        {
            var deviceId = "5a7b19df-0c9d-46bf-a104-8034b5a17182";
            var username = "test+tokenrefresh@email.com";

            await _factory.RegisterAsync(new RegisterRequestModel
            {
                Email = username,
                MasterPasswordHash = "master_password_hash",
            });

            var (_, refreshToken) = await _factory.TokenFromPasswordAsync(username, "master_password_hash", deviceId);

            var context = await _factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "refresh_token" },
                { "client_id", "web" },
                { "refresh_token", refreshToken },
            }));

            using var body = await AssertDefaultTokenBodyAsync(context);
            AssertRefreshTokenExists(body.RootElement);
        }

        [Fact]
        public async Task TokenEndpoint_GrantTypeClientCredentials_Success()
        {
            var username = "test+tokenclientcredentials@email.com";
            var deviceId = "8f14a393-edfe-40ba-8c67-a856cb89c509";

            await _factory.RegisterAsync(new RegisterRequestModel
            {
                Email = username,
                MasterPasswordHash = "master_password_hash",
            });

            var database = _factory.GetDatabaseContext();
            var user = await database.Users
                .FirstAsync(u => u.Email == username);

            var context = await _factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "client_id", $"user.{user.Id}" },
                { "client_secret", user.ApiKey },
                { "scope", "api" },
                { "DeviceIdentifier", deviceId },
                { "DeviceType", DeviceTypeAsString(DeviceType.FirefoxBrowser) },
                { "DeviceName", "firefox" },
            }));

            await AssertDefaultTokenBodyAsync(context, "api");
        }

        [Theory, BitAutoData]
        public async Task TokenEndpoint_GrantTypeClientCredentials_AsOrganization_Success(Organization organization, OrganizationApiKey organizationApiKey)
        {
            var orgRepo = _factory.Services.GetRequiredService<IOrganizationRepository>();
            organization = await orgRepo.CreateAsync(organization);
            organizationApiKey.OrganizationId = organization.Id;
            organizationApiKey.Type = OrganizationApiKeyType.Default;

            var orgApiKeyRepo = _factory.Services.GetRequiredService<IOrganizationApiKeyRepository>();
            await orgApiKeyRepo.CreateAsync(organizationApiKey);

            var context = await _factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "client_id", $"organization.{organization.Id}" },
                { "client_secret", organizationApiKey.ApiKey },
                { "scope", "api.organization" },
            }));

            Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);

            await AssertDefaultTokenBodyAsync(context, "api.organization");
        }

        [Fact]
        public async Task TokenEndpoint_GrantTypeClientCredentials_AsOrganization_BadOrgId_Fails()
        {
            var context = await _factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "client_id", "organization.bad_guid_zz&" },
                { "client_secret", "something" },
                { "scope", "api.organization" },
            }));

            Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);

            await AssertInvalidClient(context);
        }

        /// <summary>
        /// This test currently does not test any code that is not covered by other tests but 
        /// it shows that we probably have some dead code in <see cref="Core.IdentityServer.ClientStore"/>
        /// for installation, organization, and user they split on a <c>'.'</c> but have already checked that at least one
        /// <c>'.'</c> exists in the <c>client_id</c> by checking it with <see cref="string.StartsWith(string)"/> 
        /// I believe that idParts.Length > 1 will ALWAYS return true
        /// </summary>
        [Fact]
        public async Task TokenEndpoint_GrantTypeClientCredentials_AsOrganization_NoIdPart_Fails()
        {
            var context = await _factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "client_id", "organization." },
                { "client_secret", "something" },
                { "scope", "api.organization" },
            }));

            Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);

            await AssertInvalidClient(context);
        }

        [Fact]
        public async Task TokenEndpoint_GrantTypeClientCredentials_AsOrganization_OrgDoesNotExist_Fails()
        {
            var context = await _factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "client_id", $"organization.{Guid.NewGuid()}" },
                { "client_secret", "something" },
                { "scope", "api.organization" },
            }));

            Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);

            await AssertInvalidClient(context);
        }

        [Theory, BitAutoData]
        public async Task TokenEndpoint_GrantTypeClientCredentials_AsInstallation_InstallationExists_Succeeds(Installation installation)
        {
            var installationRepo = _factory.Services.GetRequiredService<IInstallationRepository>();
            installation = await installationRepo.CreateAsync(installation);

            var context = await _factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "client_id", $"installation.{installation.Id}" },
                { "client_secret", installation.Key },
                { "scope", "api.push" },
            }));

            Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
            await AssertDefaultTokenBodyAsync(context, "api.push", 24 * SecondsInHour);
        }

        [Fact]
        public async Task TokenEndpoint_GrantTypeClientCredentials_AsInstallation_InstallationDoesNotExist_Fails()
        {
            var context = await _factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "client_id", $"installation.{Guid.NewGuid()}" },
                { "client_secret", "something" },
                { "scope", "api.push" },
            }));

            Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);

            await AssertInvalidClient(context);
        }

        [Fact]
        public async Task TokenEndpoint_GrantTypeClientCredentials_AsInstallation_BadInsallationId_Fails()
        {
            var context = await _factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "client_id", "organization.bad_guid_zz&" },
                { "client_secret", "something" },
                { "scope", "api.organization" },
            }));

            Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);

            await AssertInvalidClient(context);
        }

        /// <inheritdoc cref="TokenEndpoint_GrantTypeClientCredentials_AsOrganization_NoIdPart_Fails"/>
        [Fact]
        public async Task TokenEndpoint_GrantTypeClientCredentials_AsInstallation_NoIdPart_Fails()
        {
            var context = await _factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "client_id", "installation." },
                { "client_secret", "something" },
                { "scope", "api.push" },
            }));

            Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);

            await AssertInvalidClient(context);
        }

        [Fact(Skip = "https://bitwarden.atlassian.net/browse/PS-549")]
        public async Task TokenEndpoint_GrantTypeClientCredentials_AsInternal_Success()
        {
            const string internalKey = "SPECIALKEY";
            string internalId = Guid.NewGuid().ToString();

            // Use a special factory for this test because we need to be self hosted
            var factory = new IdentityApplicationFactory
            {
                SelfHosted = true,
                DatabaseName = Guid.NewGuid().ToString(), // Generate a random database name so we don't conflict with cloud database
            };

            factory.AddConfiguration("globalSettings:internalIdentityKey", internalKey);

            var context = await factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "client_id", $"internal.{internalId}" },
                { "client_secret", internalKey },
                { "scope", "internal" },
            }));

            Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        }

        [Fact]
        public async Task TokenEndpoint_WithCaptcha_ReturnsBypass()
        {
            var username = "test+captcha@email.com";
            var deviceId = Guid.NewGuid();

            // Use a special factory so we can use a mocked ICaptchaValidationService
            var factory = new IdentityApplicationFactory();
            
            factory.SubstituteService<ICaptchaValidationService>(service =>
            {
                service
                    .RequireCaptchaValidation(Arg.Any<ICurrentContext>(), Arg.Any<User>())
                    .Returns(true);

                service
                    .ValidateCaptchaResponseAsync("test_captcha", FactoryConstants.WhitelistedIp, Arg.Any<User>())
                    .Returns(new CaptchaResponse { Success = true });

                service
                    .GenerateCaptchaBypassToken(Arg.Any<User>())
                    .Returns("bypass_token");
            });

            await factory.RegisterAsync(new RegisterRequestModel
            {
                Email = username,
                MasterPasswordHash = "master_password_hash",
                CaptchaResponse = "test_captcha",
            });

            var context = await factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "scope", "api offline_access" },
                { "client_id", "web" },
                { "deviceType", DeviceTypeAsString(DeviceType.ChromeBrowser) },
                { "deviceIdentifier", deviceId.ToString() },
                { "deviceName", "chrome" },
                { "grant_type", "password" },
                { "username", username },
                { "password", "master_password_hash" },
                { "captchaResponse", "test_captcha" }
            }), context => context.Request.Headers.Add("Auth-Email", CoreHelpers.Base64UrlEncodeString(username)));

            Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);

            using var body = await AssertDefaultTokenBodyAsync(context);
            var root = body.RootElement;
            AssertRefreshTokenExists(root);
            AssertHelper.AssertJsonProperty(root, "ForcePasswordReset", JsonValueKind.False);
            AssertHelper.AssertJsonProperty(root, "ResetMasterPassword", JsonValueKind.False);
            var kdf = AssertHelper.AssertJsonProperty(root, "Kdf", JsonValueKind.Number).GetInt32();
            Assert.Equal(0, kdf);
            var kdfIterations = AssertHelper.AssertJsonProperty(root, "KdfIterations", JsonValueKind.Number).GetInt32();
            Assert.Equal(5000, kdfIterations);
            var bypassToken = AssertHelper.AssertJsonProperty(root, "CaptchaBypassToken", JsonValueKind.String).GetString();
            Assert.Equal("bypass_token", bypassToken);
        }

        [Fact]
        public async Task TokenEndpoint_Requires2FA_BadToken_ReturnsBadRequest()
        {
            var username = "test+captcha@email.com";
            var deviceId = Guid.NewGuid();

            await _factory.RegisterAsync(new RegisterRequestModel
            {
                Email = username,
                MasterPasswordHash = "master_password_hash",
            });

            var userRepo = _factory.Services.GetRequiredService<IUserRepository>();
            var user = await userRepo.GetByEmailAsync(username);

            user.SetTwoFactorProviders(new Dictionary<TwoFactorProviderType, TwoFactorProvider>
            {
                { TwoFactorProviderType.Authenticator, new TwoFactorProvider
                {
                    Enabled = true,
                    MetaData = new Dictionary<string, object>
                    {
                        { "Key", "ORSXG5C7NNSXSMJS" }, // "test_key12" base32 encoded
                    },
                }},
            });

            await userRepo.UpsertAsync(user);

            var context = await _factory.Server.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "scope", "api offline_access" },
                { "client_id", "web" },
                { "deviceType", DeviceTypeAsString(DeviceType.ChromeBrowser) },
                { "deviceIdentifier", deviceId.ToString() },
                { "deviceName", "chrome" },
                { "grant_type", "password" },
                { "username", username },
                { "password", "master_password_hash" },
                { "TwoFactorProvider", "Authenticator" },
                { "TwoFactorToken", "bad_token" },
            }), context => context.Request.Headers.Add("Auth-Email", CoreHelpers.Base64UrlEncodeString(username)));

            Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);

            using var body = await AssertHelper.AssertResponseTypeIs<JsonDocument>(context);
            var root = body.RootElement;
            var error = AssertHelper.AssertJsonProperty(root, "error", JsonValueKind.String).GetString();
            Assert.Equal("invalid_grant", error);
            var errorDescription = AssertHelper.AssertJsonProperty(root, "error_description", JsonValueKind.String).GetString();
            Assert.Equal("invalid_username_or_password", errorDescription);
            var errorModelElement = AssertHelper.AssertJsonProperty(root, "ErrorModel", JsonValueKind.Object);
        }


        private static string DeviceTypeAsString(DeviceType deviceType)
        {
            return ((int)deviceType).ToString();
        }

        private static async Task<JsonDocument> AssertDefaultTokenBodyAsync(HttpContext httpContext, string expectedScope = "api offline_access", int expectedExpiresIn = SecondsInHour * 1)
        {
            var body = await AssertHelper.AssertResponseTypeIs<JsonDocument>(httpContext);
            var root = body.RootElement;

            Assert.Equal(JsonValueKind.Object, root.ValueKind);
            AssertAccessTokenExists(root);
            AssertExpiresIn(root, expectedExpiresIn);
            AssertTokenType(root);
            AssertScope(root, expectedScope);
            return body;
        }

        private static async Task AssertInvalidClient(HttpContext httpContext)
        {
            using var body = await AssertHelper.AssertResponseTypeIs<JsonDocument>(httpContext);
            var root = body.RootElement;

            var error = AssertHelper.AssertJsonProperty(root, "error", JsonValueKind.String).GetString();
            Assert.Equal("invalid_client", error);
        }

        private static void AssertTokenType(JsonElement tokenResponse)
        {
            var tokenTypeProperty = AssertHelper.AssertJsonProperty(tokenResponse, "token_type", JsonValueKind.String).GetString();
            Assert.Equal("Bearer", tokenTypeProperty);
        }

        private static int AssertExpiresIn(JsonElement tokenResponse, int expectedExpiresIn = 3600)
        {
            var expiresIn = AssertHelper.AssertJsonProperty(tokenResponse, "expires_in", JsonValueKind.Number).GetInt32();
            Assert.Equal(expectedExpiresIn, expiresIn);
            return expiresIn;
        }

        private static string AssertAccessTokenExists(JsonElement tokenResponse)
        {
            return AssertHelper.AssertJsonProperty(tokenResponse, "access_token", JsonValueKind.String).GetString();
        }

        private static string AssertRefreshTokenExists(JsonElement tokenResponse)
        {
            return AssertHelper.AssertJsonProperty(tokenResponse, "refresh_token", JsonValueKind.String).GetString();
        }

        private static string AssertScopeExists(JsonElement tokenResponse)
        {
            return AssertHelper.AssertJsonProperty(tokenResponse, "scope", JsonValueKind.String).GetString();
        }

        private static void AssertScope(JsonElement tokenResponse, string expectedScope)
        {
            var actualScope = AssertScopeExists(tokenResponse);
            Assert.Equal(expectedScope, actualScope);
        }
    }
}
