using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4.Models;
using IdentityServer4.Test;
using IdentityServerHost.Quickstart.UI;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddIdentityServer(options =>
                {
                    options.AccessTokenJwtType = "JWT";
                    options.EmitStaticAudienceClaim = true;
                })
                .AddInMemoryClients(GetClients())
                .AddInMemoryIdentityResources(GetIdentityResources())
                .AddTestUsers(GetUsers())
                .AddInMemoryApiResources(GetApiResources())
                .AddInMemoryApiScopes(GetApiScopes())
                .AddDeveloperSigningCredential();

            services.AddControllersWithViews();
        }

        private IEnumerable<ApiScope> GetApiScopes()
        {
            return new ApiScope[]
            {
               new ApiScope("serviceapi", "serviec api scope"),
            };
        }

        private IEnumerable<ApiResource> GetApiResources()
        {
            return new ApiResource[]
             {
                new ApiResource("serviceapi", "Service API")
                {
                    ApiSecrets = new Secret[]
                    {
                        new Secret("secret".Sha256())
                    }
                }
             };
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseStaticFiles();
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();
            app.UseIdentityServer();
            app.UseAuthorization();

            app.UseEndpoints(endpoints => endpoints.MapDefaultControllerRoute());
        }

        public static IEnumerable<Client> GetClients()
        {
            return new List<Client>
            {
                new Client
                {
                    ClientId = "Client_Two",
                    AllowedGrantTypes = GrantTypes.Hybrid,
                    AllowOfflineAccess = true,
                    RequireClientSecret = true,
                    UpdateAccessTokenClaimsOnRefresh = true,
                    RedirectUris =
                    {
                        "https://scl.com/home"
                    },
                    PostLogoutRedirectUris =
                    {
                        "https://scl.com"
                    },
                    FrontChannelLogoutUri = "https://scl.com/home/FrontLogout",
                    ClientSecrets =
                    {
                        new Secret("password".Sha256())
                    },
                    AllowedScopes =
                    {
                        "openid",
                        "profile",
                        "email",
                        "roles",
                        "name",
                        "serviceapi"
                    },
                    RequirePkce = true,
                    AllowPlainTextPkce = false,
                    AllowAccessTokensViaBrowser = true,
                    AlwaysSendClientClaims =  true,
                    AlwaysIncludeUserClaimsInIdToken =  true

                }
            };
        }

        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new[]
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email(),
                new IdentityResource
                {
                    Name = "roles",
                    UserClaims = new List<string> { "role" }
                }
            };
        }
        public static List<TestUser> GetUsers()
        {
            return new List<TestUser> {
                new TestUser {
                    SubjectId = $"userid-{Guid.NewGuid()}",
                    Username = "username",
                    Password = "password",
                    Claims = new List<Claim> {
                        new Claim(JwtClaimTypes.Name,"testuser"),
                        new Claim(JwtClaimTypes.Email, "email@email.com"),
                        new Claim("role", "admin"),
                        new Claim("role", "admin2")
                    }
                }
            };
        }
    }
}
