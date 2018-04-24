using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Identity.Client;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using System.Diagnostics;

namespace WebApp_OpenIDConnect_DotNet
{
    public static class AzureAdB2CAuthenticationBuilderExtensions
    {
        public static AuthenticationBuilder AddAzureAdB2C(this AuthenticationBuilder builder)
            => builder.AddAzureAdB2C(_ =>
            {
            });

        public static AuthenticationBuilder AddAzureAdB2C(this AuthenticationBuilder builder, Action<AzureAdB2COptions> configureOptions)
        {
            builder.Services.Configure(configureOptions);
            builder.Services.AddSingleton<IConfigureOptions<OpenIdConnectOptions>, OpenIdConnectOptionsSetup>();
            builder.AddOpenIdConnect();
            return builder;
        }

        public class OpenIdConnectOptionsSetup : IConfigureNamedOptions<OpenIdConnectOptions>
        {

            public OpenIdConnectOptionsSetup(IOptions<AzureAdB2COptions> b2cOptions)
            {
                AzureAdB2COptions = b2cOptions.Value;
            }

            public AzureAdB2COptions AzureAdB2COptions { get; set; }

            public void Configure(string name, OpenIdConnectOptions options)
            {
                options.ClientId = AzureAdB2COptions.ClientId;
                options.Authority = AzureAdB2COptions.Authority;
                options.UseTokenLifetime = true;
                options.TokenValidationParameters = new TokenValidationParameters() { NameClaimType = "name" };
                options.Events = new OpenIdConnectEvents()
                {
                    OnTokenValidated = r =>
                        {
                            Console.WriteLine($"    OnTokenValidated: {r.Principal.Identity.Name}");
                            return Task.FromResult(0);
                        },

                    OnRedirectToIdentityProvider = OnRedirectToIdentityProvider,
                    OnRedirectToIdentityProviderForSignOut = OnRedirectToIdentityProviderForSignOut,
                    OnRemoteSignOut = OnRemoteSignOut,
                    OnRemoteFailure = OnRemoteFailure,
                    OnAuthorizationCodeReceived = OnAuthorizationCodeReceived,
                    OnTicketReceived = OnTicketReceived
                };
            }

            private Task OnRedirectToIdentityProviderForSignOut(RedirectContext redirectContext)
            {
                Console.WriteLine($"    OnRedirectToIdentityProviderForSignOut: {redirectContext.ProtocolMessage.Display}");

                if (redirectContext.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                {
                    var idTokenHint = redirectContext.Request.HttpContext.User.FindFirst("id_token");
                    if (idTokenHint != null)
                        redirectContext.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                }
                return Task.FromResult(0);
            }

            private Task OnRemoteSignOut(RemoteSignOutContext arg)
            {
                Console.WriteLine($"    OnRemoteSignOut: {arg.Principal.Identity.Name}");
                return Task.CompletedTask;
            }

            public void Configure(OpenIdConnectOptions options)
            {
                Configure(Options.DefaultName, options);
            }

            /// <summary>
            /// See https://login.microsoftonline.com/NOLttcUATb2c.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=b2c_1_sign_in
            /// for out AD B2C configuration.
            /// 
            /// Perhaps we should hit, 
            /// <code>
            /// end_session_endpoint: "https://login.microsoftonline.com/nolttcuatb2c.onmicrosoft.com/oauth2/v2.0/logout?p=b2c_1_sign_in"
            /// </code>
            /// instead of:
            /// <code>authorization_endpoint: "https://login.microsoftonline.com/nolttcuatb2c.onmicrosoft.com/oauth2/v2.0/authorize?p=b2c_1_sign_in"</code>
            /// ?
            /// Also, possibly need a code block that checks if it's a logout:
            /// <code>
            /// if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest)
            /// {
            ///     // hit this, context.ProtocolMessage.IssuerAddress = AzureAdB2COptions.EndSessionEndpoint;
            ///     // having built this `logout?p=b2c_1_sign_in` bit via config.
            /// }
            /// </code>
            /// </summary>
            public Task OnRedirectToIdentityProvider(RedirectContext context)
            {
                Console.WriteLine($"    OnRedirectToIdentityProvider: {context.ProtocolMessage.UserId}");

                var defaultPolicy = AzureAdB2COptions.DefaultPolicy;
                if (context.Properties.Items.TryGetValue(
                        AzureAdB2COptions.PolicyAuthenticationProperty,
                        out var policy) && !policy.Equals(defaultPolicy))
                {
                    context.ProtocolMessage.Scope = OpenIdConnectScope.OpenIdProfile;
                    context.ProtocolMessage.ResponseType = OpenIdConnectResponseType.IdToken;
                    context.ProtocolMessage.IssuerAddress = context.ProtocolMessage.IssuerAddress.ToLower()
                        .Replace(defaultPolicy.ToLower(), policy.ToLower());
                    context.Properties.Items.Remove(AzureAdB2COptions.PolicyAuthenticationProperty);
                }
                else if (!string.IsNullOrEmpty(AzureAdB2COptions.ApiUrl))
                {
                    context.ProtocolMessage.Scope += $" offline_access {AzureAdB2COptions.ApiScopes}";
                    context.ProtocolMessage.ResponseType = OpenIdConnectResponseType.CodeIdToken;
                }

                return Task.FromResult(0);
            }

            public Task OnRemoteFailure(RemoteFailureContext context)
            {
                context.HandleResponse();
                // Handle the error code that Azure AD B2C throws when trying to reset a password from the login page 
                // because password reset is not supported by a "sign-up or sign-in policy"
                if (context.Failure is OpenIdConnectProtocolException && context.Failure.Message.Contains("AADB2C90118"))
                {
                    // If the user clicked the reset password link, redirect to the reset password route
                    context.Response.Redirect("/Session/ResetPassword");
                }
                else if (context.Failure is OpenIdConnectProtocolException && context.Failure.Message.Contains("access_denied"))
                {
                    context.Response.Redirect("/");
                }
                else
                {
                    context.Response.Redirect("/Home/Error?message=" + context.Failure.Message);
                }
                return Task.FromResult(0);
            }

            public Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedContext context)
            {
                Console.WriteLine($"    OnAuthorizationCodeReceived: {context.Principal.Identity.Name}");

                // Use MSAL to swap the code for an access token
                // Extract the code from the response notification
                var code = context.ProtocolMessage.Code;
                string signedInUserID = context.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;
                Console.WriteLine($"    Auth code received: {signedInUserID}");
                return Task.CompletedTask;
            }

            private Task OnTicketReceived(TicketReceivedContext r)
            {
                Console.WriteLine($"    OnTicketReceived: {r.Principal.Identity.Name}");
                return Task.CompletedTask;
            }
        }
    }
}
