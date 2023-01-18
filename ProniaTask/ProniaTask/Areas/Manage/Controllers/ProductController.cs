using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using ProniaTask.DAL;
using ProniaTask.Models;
using ProniaTask.Utilities;
using ProniaTask.ViewModels;

namespace ProniaTask.Areas.Manage.Controllers
{
    [Area("Manage")]
    [Authorize(Roles = "Moderator,Admin")]
    public class ProductController : Controller
    {
        AppDbContext _context { get; }
        IWebHostEnvironment _env { get; }
        public ProductController(AppDbContext context, IWebHostEnvironment env)
        {
            _context = context;
            _env = env;
        }
        public IActionResult Index(int page = 1)
        {
            PaginateVM<Product> paginateVM = new PaginateVM<Product>();
            paginateVM.MaxPageCount = (int)Math.Ceiling((decimal)_context.Products.Count() / 5);
            paginateVM.CurrentPage = page;
            if (page > paginateVM.MaxPageCount || page < 1) return BadRequest();
            paginateVM.Items = _context.Products?.Skip((page - 1) * 5).Take(5).Include(p => p.ProductColors).ThenInclude(pc => pc.Color)
                .Include(p => p.ProductCategories).ThenInclude(pc => pc.Category).
                Include(p => p.ProductSizes).ThenInclude(ps => ps.Size).Include(p => p.ProductImages).Where(p => p.IsDeleted == false);
            return View(paginateVM);
        }
        public IActionResult Delete(int? id)
        {
            if (id is null || id == 0) return BadRequest();
            Product exist = _context.Products.Include(p => p.ProductCategories)
                .Include(p => p.ProductSizes).Include(p => p.ProductColors)
                .Include(p => p.ProductImages).FirstOrDefault(p => p.Id == id);
            if (exist is null) return NotFound();
            foreach (ProductImage image in exist.ProductImages)
            {
                image.ImageUrl.DeleteFile(_env.WebRootPath, "assets/images/product");
            }
            _context.ProductColors.RemoveRange(exist.ProductColors);
            _context.ProductSizes.RemoveRange(exist.ProductSizes);
            _context.ProductCategories.RemoveRange(exist.ProductCategories);
            _context.ProductImages.RemoveRange(exist.ProductImages);
            exist.IsDeleted = true;
            _context.SaveChanges();
            return RedirectToAction(nameof(Index));
        }
        public IActionResult Create()
        {
            ViewBag.Colors = new SelectList(_context.Colors, nameof(Color.Id), nameof(Color.Name));
            ViewBag.Sizes = new SelectList(_context.Sizes, nameof(Size.Id), nameof(Size.Name));
            ViewBag.Categories = new SelectList(_context.Categories, nameof(Category.Id), nameof(Category.Name));
            return View();
        }
        [HttpPost]
        public IActionResult Create(CreateProductVM cp)
        {
            var coverImg = cp.CoverImage;
            var hoverImg = cp.HoverImage;
            var otherImgs = cp.OtherImages ?? new List<IFormFile>();
            string result = coverImg?.CheckValidate("image/", 600);
            if (result?.Length>0)
            {
                ModelState.AddModelError("Cover Image", result);
            }
            result = hoverImg?.CheckValidate("image/", 600);
            if (result?.Length>0)
            {
                ModelState.AddModelError("Hover Image",result);
            }
            foreach (var image in otherImgs)
            {
                result = image.CheckValidate("image/", 600);
                if (result?.Length>0)
                {
                    ModelState.AddModelError("OtherImages",result);
                }
            }
            foreach (int colorId in (cp.ColorIds ?? new List<int>()))
            {
                if (!_context.Colors.Any(c=>c.Id == colorId))
                {
                    ModelState.AddModelError("ColorIds", "There is no matched color with this id!");
                    break;
                }
            }
            foreach (int sizeId in (cp.SizeIds ?? new List<int>()))
            {
                if (!_context.Sizes.Any(c => c.Id == sizeId))
                {
                    ModelState.AddModelError("ColorIds", "There is no matched size with this id!");
                    break;
                }
            }
            foreach (int categoryId in (cp.CategoryIds ?? new List<int>()))
            {
                if (!_context.Categories.Any(c => c.Id == categoryId))
                {
                    ModelState.AddModelError("ColorIds", "There is no matched category with this id!");
                    break;
                }
            }
            if (!ModelState.IsValid) 
            {
                ViewBag.Colors = new SelectList(_context.Colors, nameof(Color.Id), nameof(Color.Name));
                ViewBag.Sizes = new SelectList(_context.Sizes, nameof(Size.Id), nameof(Size.Name));
                ViewBag.Categories = new SelectList(_context.Categories, nameof(Category.Id), nameof(Category.Name));
                return View();
            }
            var sizes = _context.Sizes.Where(s => cp.SizeIds.Contains(s.Id));
            var colors = _context.Colors.Where(c => cp.ColorIds.Contains(c.Id));
            var categories = _context.Categories.Where(ca => cp.CategoryIds.Contains(ca.Id));
            Product product = new Product
            {
                Name = cp.Name,
                CostPrice = cp.CostPrice,
                SellPrice = cp.SellPrice,
                Description = cp.Description,
                Discount = cp.Discount,
                IsDeleted = false,
                SKU = "1"
                
            };
            List<ProductImage> images = new List<ProductImage>();
            images.Add(
                new ProductImage
                {
                    ImageUrl = coverImg?.SaveFile(Path.Combine(_env.WebRootPath, "assets", "images", "product")),
                    IsCover = true,
                    Product = product
                });
            images.Add(
                new ProductImage
                {
                    ImageUrl = hoverImg?.SaveFile(Path.Combine(_env.WebRootPath, "assets", "images", "product")),
                    IsCover = false,
                    Product = product
                });
            foreach (var item in otherImgs)
            {
                images.Add(
                    new ProductImage
                    {
                        ImageUrl = item?.SaveFile(Path.Combine(_env.WebRootPath, "assets", "images", "product")),
                        IsCover = null,
                        Product = product
                    });
            }
            product.ProductImages = images;
            _context.Products.Add(product);
            foreach (var item in colors)
            {
                _context.ProductColors.Add(new ProductColor { Product = product, ColorId = item.Id });
            }
            foreach (var item in sizes)
            {
                _context.ProductSizes.Add(new ProductSize { Product = product, SizeId = item.Id });
            }
            foreach (var item in categories)
            {
                _context.ProductCategories.Add(new ProductCategory { Product = product, CategoryId = item.Id });
            }
            _context.SaveChanges();
            return RedirectToAction(nameof(Index));
        }
        public IActionResult Update(int? id)
        {
            if (id is null || id == 0) return BadRequest();
            var product = _context.Products.Include(p=>p.ProductCategories).Include(p=>p.ProductColors).Include(p=>p.ProductSizes)
                .Include(p=>p.ProductImages).FirstOrDefault(p => p.Id == id);
            if (product is null) return NotFound();
            UpdateProductVM updateProduct = new UpdateProductVM
            {
                Id = product.Id,
                Name = product.Name,
                CostPrice = product.CostPrice,
                SellPrice = product.SellPrice,
                Description = product.Description,
                Discount = product.Discount,
                ProductImages =product.ProductImages.ToList(),
                ColorIds = product.ProductColors.Select(pc=>pc.ColorId).ToList(),
                SizeIds = product.ProductSizes.Select(pc => pc.SizeId).ToList(),
                CategoryIds = product.ProductCategories.Select(pc => pc.CategoryId).ToList()
            };
            ViewBag.Colors = new SelectList(_context.Colors, nameof(Color.Id), nameof(Color.Name));
            ViewBag.Sizes = new SelectList(_context.Sizes, nameof(Size.Id), nameof(Size.Name));
            ViewBag.Categories = new SelectList(_context.Categories, nameof(Category.Id), nameof(Category.Name));
            return View(updateProduct);
        }
        [HttpPost]
        public IActionResult Update(int? id, UpdateProductVM updateProduct)
        {
            foreach (int colorId in (updateProduct.ColorIds ?? new List<int>()))
            {
                if (!_context.Colors.Any(c => c.Id == colorId))
                {
                    ModelState.AddModelError("ColorIds", "There is no matched color with this id!");
                    break;
                }
            }
            foreach (int sizeId in (updateProduct.SizeIds ?? new List<int>()))
            {
                if (!_context.Sizes.Any(c => c.Id == sizeId))
                {
                    ModelState.AddModelError("ColorIds", "There is no matched size with this id!");
                    break;
                }
            }
            foreach (int categoryId in (updateProduct.CategoryIds ?? new List<int>()))
            {
                if (!_context.Categories.Any(c => c.Id == categoryId))
                {
                    ModelState.AddModelError("ColorIds", "There is no matched category with this id!");
                    break;
                }
            }
            var coverImg = updateProduct.CoverImage;
            var hoverImg = updateProduct.HoverImage;
            var otherImgs = updateProduct.OtherImages ?? new List<IFormFile>();
            string result = coverImg?.CheckValidate("image/", 600);
            if (result?.Length > 0)
            {
                ModelState.AddModelError("Cover Image", result);
            }
            result = hoverImg?.CheckValidate("image/", 600);
            if (result?.Length > 0)
            {
                ModelState.AddModelError("Hover Image", result);
            }
            foreach (var image in otherImgs)
            {
                result = image.CheckValidate("image/", 600);
                if (result?.Length > 0)
                {
                    ModelState.AddModelError("OtherImages", result);
                }
            }
            if (!ModelState.IsValid)
            {
                ViewBag.Colors = new SelectList(_context.Colors, nameof(Color.Id), nameof(Color.Name));
                ViewBag.Sizes = new SelectList(_context.Sizes, nameof(Size.Id), nameof(Size.Name));
                ViewBag.Categories = new SelectList(_context.Categories, nameof(Category.Id), nameof(Category.Name));
                return View();
            }
            var product = _context.Products.Include(p => p.ProductCategories).Include(p => p.ProductColors).Include(p => p.ProductSizes)
                .Include(p => p.ProductImages).FirstOrDefault(p => p.Id == id);
            if (product is null) return NotFound();
            foreach (var item in product.ProductColors)
            {
                if (updateProduct.ColorIds.Contains(item.ColorId))
                {
                    updateProduct.ColorIds.Remove(item.ColorId);
                }
                else
                {
                    _context.ProductColors.Remove(item);
                }
            }
            foreach (var colorId in updateProduct.ColorIds)
            {
                _context.ProductColors.Add(new ProductColor { Product = product, ColorId = colorId });
            }
            foreach (var item in product.ProductSizes)
            {
                if (updateProduct.SizeIds.Contains(item.SizeId))
                {
                    updateProduct.SizeIds.Remove(item.SizeId);
                }
                else
                {
                    _context.ProductSizes.Remove(item);
                }
            }
            foreach (var sizeId in updateProduct.SizeIds)
            {
                _context.ProductSizes.Add(new ProductSize { Product = product, SizeId = sizeId });
            }
            foreach (var item in product.ProductCategories)
            {
                if (updateProduct.CategoryIds.Contains(item.CategoryId))
                {
                    updateProduct.CategoryIds.Remove(item.CategoryId);
                }
                else
                {
                    _context.ProductCategories.Remove(item);
                }
            }
            foreach (var categoryId in updateProduct.CategoryIds)
            {
                _context.ProductCategories.Add(new ProductCategory { Product = product, CategoryId = categoryId });
            }
            List<ProductImage> images = new List<ProductImage>();
            if (coverImg != null)
            {
                var oldCover = product.ProductImages.FirstOrDefault(pi => pi.IsCover == true);
                _context.ProductImages.Remove(oldCover);
                oldCover.ImageUrl.DeleteFile(_env.WebRootPath, "assets/images/product");
                images.Add(new ProductImage
                {
                    ImageUrl = coverImg.SaveFile(Path.Combine(_env.WebRootPath, "assets", "images", "product")),
                    IsCover = true,
                    Product = product
                });
            }
            if (hoverImg != null)
            {
                var oldHover = product.ProductImages.FirstOrDefault(pi => pi.IsCover == false);
                if (oldHover != null)
                {
                    _context.ProductImages.Remove(oldHover);
                    oldHover.ImageUrl.DeleteFile(_env.WebRootPath, "assets/images/product");
                }
                images.Add(new ProductImage
                    {
                        ImageUrl = hoverImg.SaveFile(Path.Combine(_env.WebRootPath, "assets", "images", "product")),
                        IsCover = false,
                        Product = product
                    });
            }
            foreach (var item in otherImgs)
            {
                images.Add(new ProductImage
                    {
                        ImageUrl = item?.SaveFile(Path.Combine(_env.WebRootPath, "assets", "images", "product")),
                        IsCover = null,
                        Product = product
                    });
            }
            var delete = updateProduct.ImageIds;
            foreach (var item in (delete ?? new List<int>()))
            {
                foreach (var pi in product.ProductImages)
                {
                    if (pi.Id == item)
                    {
                        product.ProductImages.Remove(pi);
                        pi.ImageUrl.DeleteFile(_env.WebRootPath, "assets/images/product");
                    }
                }
            }
            foreach (var image in images)
            {
                product.ProductImages.Add(image);
            }
            product.Name = updateProduct.Name;
            product.Description = updateProduct.Description;
            product.Discount = updateProduct.Discount;
            product.CostPrice = updateProduct.CostPrice;
            product.SellPrice = updateProduct.SellPrice;
            _context.SaveChanges();
            return RedirectToAction(nameof(Index));
        }
    }

}
