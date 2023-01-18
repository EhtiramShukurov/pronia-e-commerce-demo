using Microsoft.AspNetCore.Mvc;
using ProniaTask.DAL;

namespace ProniaTask.ViewComponents
{
    public class DetailViewComponent:ViewComponent
    {
        readonly AppDbContext _context;
        public DetailViewComponent(AppDbContext context)
        {
            _context = context;
        }
        public async Task<IViewComponentResult> InvokeAsync(int id)
        {
            return View(_context.Products.FirstOrDefault(p => p.Id == id));
        }
    }
}
