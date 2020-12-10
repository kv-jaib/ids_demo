using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

[assembly: OwinStartup(typeof(Client_Two.Startup))]

namespace Client_Two
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ServicePointManager
                    .ServerCertificateValidationCallback +=
                (sender, cert, chain, sslPolicyErrors) => true;
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

            app.SetDefaultSignInAsAuthenticationType("cookie");

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "cookie"
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions()
            {
                Authority = "https://localhost:44349/",
                RedirectUri = "https://scl.com/home",
                PostLogoutRedirectUri = "https://scl.com/home",
                ClientId = "Client_Two",
                ClientSecret = "password",
                ResponseType = "code id_token token",
                Scope = $"openid profile roles email serviceapi",
                SaveTokens = true,
                SignInAsAuthenticationType = "cookie",
                UseTokenLifetime = false,
                RedeemCode = true,
                Notifications = new OpenIdConnectAuthenticationNotifications()
                {
                    RedirectToIdentityProvider = n =>
                    {
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication)
                        {
                            // generate code verifier and code challenge
                            var codeVerifier = CryptoRandom.CreateUniqueId(32);

                            string codeChallenge;
                            using (var sha256 = SHA256.Create())
                            {
                                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                                codeChallenge = Base64Url.Encode(challengeBytes);
                            }

                            // set code_challenge parameter on authorization request
                            n.ProtocolMessage.SetParameter("code_challenge", codeChallenge);
                            n.ProtocolMessage.SetParameter("code_challenge_method", "S256");

                            // remember code verifier in cookie (adapted from OWIN nonce cookie)
                            // see: https://github.com/scottbrady91/Blog-Example-Classes/blob/master/AspNetFrameworkPkce/ScottBrady91.BlogExampleCode.AspNetPkce/Startup.cs#L85
                            RememberCodeVerifier(n, codeVerifier);
                        } 
                        else if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                        {
                            n.ProtocolMessage.IdTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token")?.Value;
                            //n.ProtocolMessage.PostLogoutRedirectUri = "https://scl.com/home";
                        }

                        return Task.CompletedTask;
                    },
                    SecurityTokenValidated = notification =>
                    {
                        notification.AuthenticationTicket.Identity.AddClaim(new Claim("id_token", notification.ProtocolMessage.IdToken));
                        notification.AuthenticationTicket.Identity.AddClaim(new Claim("access_token", notification.ProtocolMessage.AccessToken));

                        return Task.FromResult(0);
                    },
                    AuthorizationCodeReceived = n =>
                    {
                        // get code verifier from cookie
                        // see: https://github.com/scottbrady91/Blog-Example-Classes/blob/master/AspNetFrameworkPkce/ScottBrady91.BlogExampleCode.AspNetPkce/Startup.cs#L102
                        var codeVerifier = RetrieveCodeVerifier(n);

                        // attach code_verifier on token request
                        n.TokenEndpointRequest.SetParameter("code_verifier", codeVerifier);

                        return Task.CompletedTask;
                    }

                },
                TokenValidationParameters = new TokenValidationParameters()
                {
                    NameClaimType = JwtClaimTypes.Name
                }
            });
        }

        private void RememberCodeVerifier(RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> n, string codeVerifier)
        {
            var properties = new AuthenticationProperties();
            properties.Dictionary.Add("cv", codeVerifier);
            n.Options.CookieManager.AppendResponseCookie(
                n.OwinContext,
                GetCodeVerifierKey(n.ProtocolMessage.State),
                Convert.ToBase64String(Encoding.UTF8.GetBytes(n.Options.StateDataFormat.Protect(properties))),
                new CookieOptions
                {
                    SameSite = SameSiteMode.None,
                    HttpOnly = true,
                    Secure = n.Request.IsSecure,
                    Expires = DateTime.UtcNow + n.Options.ProtocolValidator.NonceLifetime
                });
        }

        private string RetrieveCodeVerifier(AuthorizationCodeReceivedNotification n)
        {
            string key = GetCodeVerifierKey(n.ProtocolMessage.State);

            string codeVerifierCookie = n.Options.CookieManager.GetRequestCookie(n.OwinContext, key);
            if (codeVerifierCookie != null)
            {
                var cookieOptions = new CookieOptions
                {
                    SameSite = SameSiteMode.None,
                    HttpOnly = true,
                    Secure = n.Request.IsSecure
                };

                n.Options.CookieManager.DeleteCookie(n.OwinContext, key, cookieOptions);
            }

            var cookieProperties = n.Options.StateDataFormat.Unprotect(Encoding.UTF8.GetString(Convert.FromBase64String(codeVerifierCookie)));
            cookieProperties.Dictionary.TryGetValue("cv", out var codeVerifier);

            return codeVerifier;
        }

        private string GetCodeVerifierKey(string state)
        {
            using (var hash = SHA256.Create())
            {
                return OpenIdConnectAuthenticationDefaults.CookiePrefix + "cv." + Convert.ToBase64String(hash.ComputeHash(Encoding.UTF8.GetBytes(state)));
            }
        }
    }
}
