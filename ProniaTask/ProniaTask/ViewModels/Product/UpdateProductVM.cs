﻿using ProniaTask.Models;
using System.ComponentModel.DataAnnotations;

namespace ProniaTask.ViewModels
{
    public class UpdateProductVM
    {
        public int Id { get; set; }
        [StringLength(20), Required]
        public string Name { get; set; }
        [StringLength(500), Required]
        public string Description { get; set; }
        public double CostPrice { get; set; }
        public double SellPrice { get; set; }
        public double Discount { get; set; }
        public IFormFile? CoverImage { get; set; }
        public IFormFile? HoverImage { get; set; }
        public ICollection<IFormFile>? OtherImages { get; set; }
        public ICollection<ProductImage>? ProductImages { get; set; }
        public List<int>? ImageIds { get; set; }
        public List<int> ColorIds { get; set; }
        public List<int> SizeIds { get; set; }
        public List<int> CategoryIds { get; set; }
    }
}
