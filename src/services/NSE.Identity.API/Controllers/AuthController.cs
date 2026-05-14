using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using static NSE.Identity.API.Models.UserViewModels;

namespace NSE.Identity.API.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : Controller
    {

        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public AuthController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserRegister userRegister)
        {
           if(!ModelState.IsValid) return BadRequest();
            
            var user = new IdentityUser
            {
                UserName = userRegister.Email,
                Email = userRegister.Email,
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user, userRegister.Password);

            if(result.Succeeded)
            {
                await _signInManager.SignInAsync(user, false);
                return Ok();
            }

            return BadRequest();
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserLogin userLogin)
        {
            if (!ModelState.IsValid) return BadRequest();

            var result = await _signInManager.PasswordSignInAsync(
                userLogin.Email,
                userLogin.Password,
                false, 
                true);

            if (result.Succeeded)
            {
                return Ok();
            }

            return BadRequest();
        }
    }
}
