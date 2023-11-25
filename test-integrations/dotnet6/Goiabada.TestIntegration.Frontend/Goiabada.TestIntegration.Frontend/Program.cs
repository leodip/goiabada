using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

internal class Program
{
    private static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddHttpContextAccessor();
        builder.Services.AddHttpClient(Options.DefaultName, client => { })
        .ConfigurePrimaryHttpMessageHandler(() =>
        {
            // FOR DEVELOPMENT ONLY: Accept invalid (self signed) SSL certificates
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => { return true; }
            };
            return handler;
        });

        ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
        IdentityModelEventSource.ShowPII = true;        

        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
        builder.Services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.Cookie.SameSite = SameSiteMode.Strict;

            options.Events = new CookieAuthenticationEvents
            {
                OnValidatePrincipal = async context =>
                {
                    var tokens = context.Properties.GetTokens();
                    var accessToken = tokens.FirstOrDefault(t => t.Name == "access_token");
                    var refreshToken = tokens.FirstOrDefault(t => t.Name == "refresh_token");

                    if (refreshToken != null && accessToken != null)
                    {
                        var handler = new JwtSecurityTokenHandler();
                        var jwtSecurityToken = handler.ReadJwtToken(accessToken.Value);
                        var expClaim = jwtSecurityToken.Claims.FirstOrDefault(c => c.Type == "exp");
                        if (expClaim == null)
                        {
                            return;
                        }
                        var expDate = DateTimeOffset.FromUnixTimeSeconds(long.Parse(expClaim.Value));
                        if (expDate < DateTimeOffset.UtcNow)
                        {
                            // token is expired, let's attempt to renew
                            var httpClient = context.HttpContext.RequestServices.GetRequiredService<IHttpClientFactory>().CreateClient();
                            var requestData = new[]
                            {
                                new KeyValuePair<string, string>("client_id", builder.Configuration["OpenIDConnect:ClientId"]),
                                new KeyValuePair<string, string>("client_secret", builder.Configuration["OpenIDConnect:ClientSecret"]),
                                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                                new KeyValuePair<string, string>("refresh_token", refreshToken.Value),
                            };

                            httpClient.DefaultRequestHeaders.Add("accept", "application/json");

                            var tokenEndpoint = builder.Configuration["OpenIDConnect:TokenEndpoint"];
                            try
                            {
                                var response = await httpClient.PostAsync(tokenEndpoint, new FormUrlEncodedContent(requestData));
                                if (!response.IsSuccessStatusCode)
                                {
                                    context.RejectPrincipal();
                                    return;
                                }

                                var json = await response.Content.ReadAsStringAsync() ?? "{}";
                                var jsonNode = JsonNode.Parse(json);
                                if (jsonNode != null)
                                {

                                    if (jsonNode["error"] != null)
                                    {
                                        context.RejectPrincipal();
                                        return;
                                    }

                                    var newAccessToken = jsonNode["access_token"]?.ToString();
                                    var newIdToken = jsonNode["id_token"]?.ToString();
                                    var newRefreshToken = jsonNode["refresh_token"]?.ToString();
                                    var newExp = jsonNode["expires_in"]?.ToString();

                                    if (newAccessToken != null && newIdToken != null && newRefreshToken != null && newExp != null)
                                    {
                                        var newTokens = new List<AuthenticationToken>
                                    {
                                        new() { Name = "access_token", Value = newAccessToken },
                                        new() { Name = "id_token", Value = newIdToken },
                                        new() { Name = "refresh_token", Value = newRefreshToken },
                                        new() { Name = "expires_at", Value = DateTimeOffset.UtcNow.AddSeconds(int.Parse(newExp)).ToString("o", System.Globalization.CultureInfo.InvariantCulture) }
                                    };
                                        context.Properties.StoreTokens(newTokens);
                                        context.ShouldRenew = true;
                                    }
                                }
                            }
                            catch (Exception)
                            {                                
                                context.RejectPrincipal();
                                return;
                            }
                        }
                    }
                }
            };
        })
        .AddOpenIdConnect(options =>
        {
            options.Authority = builder.Configuration["OpenIDConnect:Issuer"];
            options.ClientId = builder.Configuration["OpenIDConnect:ClientId"];
            options.ClientSecret = builder.Configuration["OpenIDConnect:ClientSecret"];
            options.ResponseType = OpenIdConnectResponseType.Code;
            options.ResponseMode = OpenIdConnectResponseMode.Query;
            options.Scope.Clear();
            var scope = builder.Configuration["OpenIDConnect:Scope"];
            if (!string.IsNullOrEmpty(scope))
            {
                foreach (var s in scope.Split(' '))
                {
                    options.Scope.Add(s);
                }
            }

            options.GetClaimsFromUserInfoEndpoint = true;
            options.SaveTokens = true;

            options.TokenValidationParameters = new TokenValidationParameters
            {
                NameClaimType = "name",
                RoleClaimType = "groups"
            };

            // FOR DEVELOPMENT ONLY: Accept invalid (self signed) SSL certificates
            options.BackchannelHttpHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = delegate { return true; }
            };
        });

        builder.Services.AddRazorPages();

        var app = builder.Build();

        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseStaticFiles();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapRazorPages();

        app.Run();
    }
}