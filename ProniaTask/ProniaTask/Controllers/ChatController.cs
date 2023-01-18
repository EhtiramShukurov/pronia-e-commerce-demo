using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using ProniaTask.Models;

namespace ProniaTask.Controllers
{
    [Authorize]
    public class ChatController : Controller
    {
        UserManager<AppUser> _userManager;

        public ChatController(UserManager<AppUser> userManager)
        {
            _userManager = userManager;
        }

        public IActionResult Index()
        {
            ViewBag.CurrentUser =User.Identity.Name;
            return View(_userManager.Users);
        }
    }
}
