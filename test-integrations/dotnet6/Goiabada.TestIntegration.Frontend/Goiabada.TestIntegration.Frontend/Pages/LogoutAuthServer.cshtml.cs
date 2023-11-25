using System.Security.Cryptography;
using System.Text;
using CryptoNet;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MyApp.Namespace
{
    public class LogoutAuthServerModel : PageModel
    {
        private readonly IConfiguration _configuration;

        public LogoutAuthServerModel(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task<IActionResult> OnGet()
        {
            var claimsPrincipal = this.User;

            var authServerLogoutUrl = _configuration["OpenIDConnect:Issuer"] + "/auth/logout";
            var idToken = await this.HttpContext.GetTokenAsync("id_token") ?? string.Empty;
            var postLogoutRedirectUri = this.Url.Page("/LogoutFrontend", pageHandler: null, values: null, protocol: Request.Scheme);

            var random = new Random();
            var state = random.Next(); // you can have anything as state, it will be echoed back to you in the redirect

            // first option: unencrypted id token (will expose the id token client side)
            // return Redirect($"{authServerLogoutUrl}?id_token_hint={System.Net.WebUtility.UrlEncode(idToken)}&post_logout_redirect_uri={System.Net.WebUtility.UrlEncode(postLogoutRedirectUri)}&state={state}");

            // second option (recommended): encrypted id token with symmetric encryption using client secret as key
            // in this case, the client_id parameter must be passed to the logout endpoint
            var idTokenEnc = AesGsmEncryption(idToken, _configuration["OpenIDConnect:ClientSecret"]);
            var clientId = _configuration["OpenIDConnect:ClientId"];
            return Redirect($"{authServerLogoutUrl}?id_token_hint={System.Net.WebUtility.UrlEncode(idTokenEnc)}&client_id={clientId}&post_logout_redirect_uri={System.Net.WebUtility.UrlEncode(postLogoutRedirectUri)}&state={state}");
        }

        private static string AesGsmEncryption(string idTokenUnencrypted, string clientSecret)
        {
            var key = new byte[32];
            
            // use the first 32 bytes of the client secret as key
            var keyBytes = Encoding.UTF8.GetBytes(clientSecret);
            Array.Copy(keyBytes, key, Math.Min(keyBytes.Length, key.Length));

            // random nonce
            var nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; // MaxSize = 12
            RandomNumberGenerator.Fill(nonce);

            using var aes = new AesGcm(key);
            var cipherText = new byte[idTokenUnencrypted.Length];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize]; // MaxSize = 16
            aes.Encrypt(nonce, Encoding.UTF8.GetBytes(idTokenUnencrypted), cipherText, tag);

            // concatenate nonce (12 bytes) + ciphertext (? bytes) + tag (16 bytes)
            var encrypted = new byte[nonce.Length + cipherText.Length + tag.Length];
            Array.Copy(nonce, encrypted, nonce.Length);
            Array.Copy(cipherText, 0, encrypted, nonce.Length, cipherText.Length);
            Array.Copy(tag, 0, encrypted, nonce.Length + cipherText.Length, tag.Length);

            return Convert.ToBase64String(encrypted);
        }
    }
}
