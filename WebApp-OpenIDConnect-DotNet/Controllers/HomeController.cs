using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Identity.Client;
using System.Security.Claims;
// using WebApp_OpenIDConnect_DotNet.Models;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Net;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Http;

namespace WebApp_OpenIDConnect_DotNet.Controllers
{
    public class HomeController : Controller
    {
        AzureAdB2COptions AzureAdB2COptions;
        public HomeController(IOptions<AzureAdB2COptions> azureAdB2COptions)
        {
            AzureAdB2COptions = azureAdB2COptions.Value;
        }

        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult About()
        {
            ViewData["Message"] = String.Format("Claims available for the user {0}", (User.FindFirst("name")?.Value));
            return View();
        }

        public IActionResult Error(string message)
        {
            ViewBag.Message = message;
            return View();
        }
    }
}
