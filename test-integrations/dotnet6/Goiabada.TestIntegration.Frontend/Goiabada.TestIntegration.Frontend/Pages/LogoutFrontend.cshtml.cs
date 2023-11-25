using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MyApp.Namespace
{
    public class LogoutFrontendModel : PageModel
    {
        public async Task<IActionResult> OnGet()
        {            
            await this.HttpContext.SignOutAsync("Cookies");
            return Redirect("/");
        }
    }
}
