using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Identity.Client;

namespace MyApp.Namespace
{
    [Authorize]
    public class WeatherModel : PageModel
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private readonly IMemoryCache _memoryCache;

        public string WeatherForecastJson { get; set; } = default!;

        public WeatherModel(IHttpClientFactory httpClientFactory, IConfiguration configuration, IMemoryCache memoryCache)
        {
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _memoryCache = memoryCache;
        }


        public async Task OnGet()
        {
            var weatherForecast = await GetWeatherForecastAsync();
            this.WeatherForecastJson = FormatJsonText(weatherForecast);
        }

        static string FormatJsonText(string jsonString)
        {
            using var doc = JsonDocument.Parse(
                jsonString,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = true
                }
            );
            MemoryStream memoryStream = new MemoryStream();
            using (
                var utf8JsonWriter = new Utf8JsonWriter(
                    memoryStream,
                    new JsonWriterOptions
                    {
                        Indented = true
                    }
                )
            )
            {
                doc.WriteTo(utf8JsonWriter);
            }
            return new System.Text.UTF8Encoding()
                .GetString(memoryStream.ToArray());
        }

        private async Task<string> GetWeatherForecastAsync()
        {
            var url = _configuration["WeatherForecastService:Url"];
            var accessToken = await GetAccessTokenAsync();

            var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Add("accept", "application/json");

            // add bearer token in the authorization header
            httpClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", accessToken);

            var response = await httpClient.GetAsync(url);
            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync();
                throw new ApplicationException("Error calling the weather forecast service: status " + response.StatusCode +
                    " - " + body);
            }

            var json = await response.Content.ReadAsStringAsync() ?? "{}";
            return json;
        }

        private async Task<string> GetAccessTokenAsync()
        {
            var cacheKey = "weather-forecast-access-token";
            if (!_memoryCache.TryGetValue(cacheKey, out string accessTokenFromCache))
            {
                var scope = _configuration["WeatherForecastService:Scope"];
                var tokenEndpoint = _configuration["WeatherForecastService:TokenEndpoint"];
                var clientId = _configuration["WeatherForecastService:ClientId"];
                var clientSecret = _configuration["WeatherForecastService:ClientSecret"];

                var httpClient = _httpClientFactory.CreateClient();
                var requestData = new[]
                {
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("client_secret", clientSecret),
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("scope", scope),
            };

                httpClient.DefaultRequestHeaders.Add("accept", "application/json");

                var response = await httpClient.PostAsync(tokenEndpoint, new FormUrlEncodedContent(requestData));
                if (!response.IsSuccessStatusCode)
                {
                    var body = await response.Content.ReadAsStringAsync();
                    throw new ApplicationException("Error calling the weather forecast service: status " + response.StatusCode + 
                        " - " + body);
                }

                var json = await response.Content.ReadAsStringAsync() ?? "{}";
                var jsonNode = JsonNode.Parse(json) ?? throw new ApplicationException("No json found");
                if (jsonNode["error"] != null)
                {
                    // something went wrong
                    throw new ApplicationException(jsonNode["error"]?.ToString() + " - " + jsonNode["error_description"]?.ToString());
                }

                var newAccessToken = (jsonNode["access_token"]?.ToString()) ??
                    throw new ApplicationException("No access token found");

                var expires_in = (jsonNode["expires_in"]?.ToString()) ??
                    throw new ApplicationException("No expires_in found");

                var cacheEntryOptions = new MemoryCacheEntryOptions()
                    .SetAbsoluteExpiration(TimeSpan.FromSeconds(int.Parse(expires_in)));

                _memoryCache.Set(cacheKey, newAccessToken, cacheEntryOptions);
                accessTokenFromCache = newAccessToken;
            }
            return accessTokenFromCache;
        }
    }
}
