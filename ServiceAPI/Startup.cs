using System;
using System.Net;
using IdentityServer3.AccessTokenValidation;
using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(ServiceAPI.Startup))]

namespace ServiceAPI
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, error) => true;

            app.UseIdentityServerBearerTokenAuthentication(
                new IdentityServerBearerTokenAuthenticationOptions
                {
                    Authority = "https://localhost:44349",
                    ValidationMode = ValidationMode.Local,
                    RequiredScopes = new[] { "serviceapi" },
                    ClientSecret = "secret",
                    ClientId = "serviceapi",
                });

        }
    }
}