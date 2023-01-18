using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using ProniaTask.Abstractions.Services;
using ProniaTask.DAL;
using ProniaTask.Models;
using ProniaTask.ViewModels;

namespace ProniaTask.Controllers
{
    public class HomeController : Controller
    {
        AppDbContext _context { get; }
        IEmailService _emailService { get; }
        public HomeController(AppDbContext context, IEmailService emailService)
        {
            _context = context;
            _emailService = emailService;
        }
        public IActionResult Index()
        {
            ViewBag.Ids = new List<int>();
            IQueryable<Product> products = _context.Products.Where(p => !p.IsDeleted).Include(p => p.ProductImages).Take(4).AsQueryable();
            HomeVM home = new HomeVM { 
                Slides = _context.Slides.OrderBy(s=>s.Order), 
                Brands = _context.Brands,
                Clients = _context.Clients,
                Shippings = _context.Shippings,
                FeaturedProducts = products,
                LatestProducts = products.OrderByDescending(p=>p.Id)
            };
            ViewData["Banners"] = _context.Banners.ToList();
            return View(home);
        }

        public IActionResult LoadProducts(int skip = 4,int take = 4)
        {
            var products = _context.Products.Where(p => !p.IsDeleted).Include(p => p.ProductImages).Skip(skip).Take(take);
            ViewBag.ProductCount = products.Count();
            return PartialView("_ProductPartial", products);
        }
        public IActionResult QuickView(int id)
        {
            return PartialView("Detail", _context.Products.Include(p => p.ProductImages).FirstOrDefault(p=>p.Id == id));
        }
        public IActionResult SetSession(string key,string value)
        {
            HttpContext.Session.SetString(key, value);
            return Content("OK");
        }
        public IActionResult getSession(string key)
        {
            string value = HttpContext.Session.GetString(key);
            return Content(value);
        }

        public IActionResult SetCookie(string key,string value)
        {
            HttpContext.Response.Cookies.Append(key, value, new CookieOptions
            {
                MaxAge = TimeSpan.MaxValue
            }) ;
            return Content(value);

        }
        public IActionResult GetCookie(string key)
        {
            return Content(HttpContext.Request.Cookies[key]);
        }
        public IActionResult AddBasket(int? id)
        {
            List<BasketItemVM> items = new List<BasketItemVM>();
            if (!(string.IsNullOrEmpty(HttpContext.Request.Cookies["basket"])))
            {
                items = JsonConvert.DeserializeObject<List<BasketItemVM>>(HttpContext.Request.Cookies["basket"]);
            }
            BasketItemVM item = items.FirstOrDefault(i=>i.Id == id);
            if (item is null)
            {
                item = new BasketItemVM()
                {
                    Id = (int)id,
                    Count = 1
                };
                items.Add(item);
            }
            else
            {
                item.Count++;
            }
            string basket = JsonConvert.SerializeObject(items);
            HttpContext.Response.Cookies.Append("basket",basket,new CookieOptions
            {
                MaxAge=TimeSpan.FromDays(5)
            });
            return RedirectToAction(nameof(Index));
        }

        public IActionResult SendMail()
		{
            _emailService.Send("shukurovehtiram29@gmail.com", "Sample", "Just a sample message");
            return RedirectToAction(nameof(Index));
		}









        public IActionResult Shop()
        {
            //product deye controller yarat, indexi shop olacaq, detaili single product
            ViewBag.Categories = _context.Categories;
            ViewBag.Colors = _context.Colors;
            return View();
        }
        public IActionResult SingleProduct()
        {
            return View();
        }
        public IActionResult LoginRegister()
        {
            return View();
        }
        public IActionResult Cart()
        {
            return View();
        }
    }
}
