using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using IdentityModel.Client;

namespace Client_Two.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        [Authorize]
        public ActionResult Login()
        {
            ViewBag.Message = "Login";

            return View();
        }

        [AllowAnonymous]
        public void Logout()
        {
            HttpContext.GetOwinContext().Authentication.SignOut();
        }

        [AllowAnonymous]
        public ActionResult FrontLogout(string sid)
        {
            var cp = (ClaimsPrincipal)User;
            var sidClaim = cp.FindFirst("sid");
            if (sidClaim != null && sidClaim.Value == sid)
            {
                Request.GetOwinContext().Authentication.SignOut("Cookies");
            }

            return new HttpStatusCodeResult(200);
        }

        [Authorize]
        public ActionResult Contact()
        {
            var client = new HttpClient()
            {
                BaseAddress = new Uri("http://serviceapi/api/")
            };

            string accessToken = ((ClaimsIdentity) User.Identity).Claims.FirstOrDefault(x => x.Type == "access_token")?.Value;
            client.SetBearerToken(accessToken);
            string result = client.GetAsync("values").GetAwaiter().GetResult().Content.ReadAsStringAsync().Result;

            ViewBag.ServiceCallData = result;
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}