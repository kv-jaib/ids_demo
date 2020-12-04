using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Net;
using System.Security.Claims;
using IdentityModel;
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
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();
            ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, error) => true;

            var options = new IdentityServerBearerTokenAuthenticationOptions
            {
                Authority = "https://localhost:44349",
                ValidationMode = ValidationMode.Local,
                RequiredScopes = new[] {"serviceapi", "roles"},
                ClientSecret = "secret",
                ClientId = "serviceapi",
            };

            app.UseIdentityServerBearerTokenAuthentication(options);
        }
    }
}