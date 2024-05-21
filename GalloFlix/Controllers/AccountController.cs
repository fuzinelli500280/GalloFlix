using System.Net.Mail;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages;
using GalloFlix.ViewModels;

namespace GalloFlix.Controllers;

public class AccountController : Controller
{
    private readonly ILogger<AccountController> _logger;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;

    public AccountController(
        ILogger<AccountController> logger,
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager
        )
    {
        _logger = logger;
        _signInManager = signInManager;
        _userManager = userManager;
    }

    [HttpGet]
    public IActionResult Login(string returnUrl)
    {
        LoginVM loginVM = new()
        {
            ReturnUrl = returnUrl ?? Url.Content("~/")
        };
        return View(loginVM);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginVM login)
    {
        if (ModelState.IsValid)
        {
            string userName = login.Email;
            if (IsValidEmail(userName))
            {
                var user = await _userManager.FindByEmailAsync(userName);
                if (user != null)
                {
                    userName = user.UserName;
                }
            }

            var result = await _signInManager.PasswordSignInAsync(
                userName, login.Password, login.RememberMe, lockoutOnFailure: true
            );
            if (result.Succeeded)
            {
                _logger.LogInformation($"Usúario {userName} fez login");
                return LocalRedirect(login.ReturnUrl);
            }

            if (result.IsLockedOut)
            {
                _logger.LogWarning($"Usúario {userName} foi bloqueado");
                ModelState.AddModelError(string.Empty, "Conta bloqueada! Aguarde alguns minutos para tentar novamente");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Usuáruios e/ou senha inválidos");
            }

        }
        return View(login);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout(){
        _logger.LogInformation($"Usúario {ClaimTypes.Email} saiu do sistema");
        await _signInManager.SignOutAsync();
        return RedirectToAction("Index", "Home");
    }

    private static bool IsValidEmail(string email)
    {
        try
        {
            MailAddress mail = new(email);
            return true;
        }
        catch
        {
            return false;
        }
    }
}