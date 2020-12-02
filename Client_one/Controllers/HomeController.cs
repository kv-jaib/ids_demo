using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace Client_one.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
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



        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}