using ProniaTask.DAL;
using ProniaTask.Models;

namespace ProniaTask.Services
{
    public class LayoutService
    {
        readonly AppDbContext _context;
        public LayoutService(AppDbContext context)
        {
            _context = context;
        }
        public Dictionary<string,string> GetSettings()
        {
            return _context.Settings.ToDictionary(s => s.Key, s => s.Value);
        }
        public List<Product> GetProducts()
        {
            return _context.Products.ToList();
        }
    }
}
