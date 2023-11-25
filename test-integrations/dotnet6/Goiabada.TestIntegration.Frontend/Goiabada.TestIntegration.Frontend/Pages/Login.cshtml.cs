using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MyApp.Namespace
{
    // this attribute will trigger a redirect to the auth server if the user is not logged in
    [Authorize] 
    public class LoginModel : PageModel
    {        
        public IActionResult OnGet()
        {
            return Redirect("/");
        }
    }
}
