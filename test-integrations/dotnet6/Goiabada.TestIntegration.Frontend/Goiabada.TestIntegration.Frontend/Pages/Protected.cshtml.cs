using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MyApp.Namespace
{
    [Authorize]
    public class ProtectedModel : PageModel
    {
        public string GivenName { get; set; } = default!;
        public string MiddleName { get; set; } = default!;
        public string FamilyName { get; set; } = default!;
        public string Email { get; set; } = default!;        
        public string[] ClaimsFromIdToken { get; set; } = default!;     
        public string[] ClaimsFromAccessToken { get; set; } = default!;     
        public string[] ClaimsFromRefreshToken { get; set; } = default!;     

        public async Task OnGet()
        {
            var claimsPrincipal = this.User;
            
            this.GivenName = claimsPrincipal.FindFirstValue("given_name");
            this.MiddleName = claimsPrincipal.FindFirstValue("middle_name");
            this.FamilyName = claimsPrincipal.FindFirstValue("family_name");
            this.Email = claimsPrincipal.FindFirstValue("email");

            var idToken = await this.HttpContext.GetTokenAsync("id_token") ?? string.Empty;
            var accessToken = await this.HttpContext.GetTokenAsync("access_token") ?? string.Empty;
            var refreshToken = await this.HttpContext.GetTokenAsync("refresh_token") ?? string.Empty;               

            this.ClaimsFromIdToken = GetClaims(idToken);
            this.ClaimsFromAccessToken = GetClaims(accessToken);
            this.ClaimsFromRefreshToken = GetClaims(refreshToken);
        }

        private string[] GetClaims(string token) {
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(token);
            var claims = new List<string>();
            foreach (var claim in jwtSecurityToken.Claims)
            {
                var dateClaims = new[] { "exp", "iat", "auth_time", "udpated_at" };
                if(dateClaims.Contains(claim.Type)) {
                    claims.Add($"{claim.Type}: {claim.Value} ({this.ParseDateTime(claim)})");
                    continue;
                }
                claims.Add($"{claim.Type}: {claim.Value}");
            }
            return claims.ToArray();
        }

        private string ParseDateTime(Claim claim) {
            if(claim == null) {
                return string.Empty;
            }
            var dateTime = DateTimeOffset.FromUnixTimeSeconds(long.Parse(claim.Value));
            return dateTime.ToString("yyyy-MM-dd HH:mm:ss");
        }
    }
}

