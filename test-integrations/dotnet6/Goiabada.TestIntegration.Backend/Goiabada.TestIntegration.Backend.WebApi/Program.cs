using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

internal class Program
{
    private static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddControllers();
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        IdentityModelEventSource.ShowPII = true;
        builder.Services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer("Bearer", options =>
            {
                options.Authority = builder.Configuration["OAuth2:Issuer"];

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidAudience = builder.Configuration["OAuth2:ExpectedAudience"]
                };

                // FOR DEVELOPMENT ONLY: Accept invalid certificates
                options.BackchannelHttpHandler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = delegate { return true; }
                };
            });

        builder.Services.AddAuthorization(o =>
        {
            o.AddPolicy("can-get-forecast", p =>
            {
                p.RequireAssertion(c =>
                {
                    var scopeClaim = c.User.FindFirst("scope");
                    if (scopeClaim == null)
                        return false;
                    var parts = scopeClaim.Value.Split(' ');
                    return parts.Any(p => p == builder.Configuration["OAuth2:WeatherForecastReadScope"]);
                });
            });
        });

        var app = builder.Build();

        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.UseHttpsRedirection();

        app.UseAuthorization();

        app.MapControllers();

        app.Run();
    }
}