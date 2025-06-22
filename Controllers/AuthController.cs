using CrisisNet.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using CrisisNet.Models.DTO;
using CrisisNet.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authorization;
namespace CrisisNet.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext _context;
        public AuthController(ApplicationDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }
        //Register Method
        [HttpPost("register")]
        public async Task<IActionResult> Register(AddUserViewModel model)
        {
            if (model == null || string.IsNullOrEmpty(model.Username) || string.IsNullOrEmpty(model.Password) || string.IsNullOrEmpty(model.Email))
            {
                return BadRequest("Invalid user data.");
            }
            var emailexists = await _context.Users.AnyAsync(u => u.Email == model.Email);
            if (emailexists)
            {
                return BadRequest("Email already exists.");
            }
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(model.Password); // Hash the password before saving
            var user = new Models.User
            {
                Username = model.Username,
                Password = hashedPassword, // Note: Password should be hashed in a real application
                Email = model.Email,
                CreatedAt = model.CreatedAt,
                IsActive = model.IsActive
            };  
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return Ok(new { message = "User registered successfully." });
        }
        [HttpPost("login")]
        public async Task <IActionResult> Login(LoginDTO loginDTO)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == loginDTO.email);
            if (user == null || !BCrypt.Net.BCrypt.Verify(loginDTO.password, user.Password))
            {
                return Unauthorized(new { message = "Invalid email or password." });
            }
            if (user != null)
            {
                var claims = new[]
                {
                   new Claim(JwtRegisteredClaimNames.Sub, _configuration["Jwt:Subject"]),
                   new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                   new Claim("ID", user.Id.ToString()),
                   new Claim("Email", user.Email.ToString()),
                };
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
                var signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                var token = new JwtSecurityToken(
                    _configuration["Jwt:Issuer"],
                    _configuration["Jwt:Audience"],
                    claims,
                    expires: DateTime.UtcNow.AddMinutes(30),
                    signingCredentials: signIn
                );
                string tokenvalue = new JwtSecurityTokenHandler().WriteToken(token);
                user.LastLoginAt = DateTime.UtcNow; // Update last login time
                return Ok(new
                {
                    token = tokenvalue,
                    userId = user.Id,
                    username = user.Username,
                    email = user.Email,
                    lastLoginAt = user.LastLoginAt
                });
                //return Ok("user");
            }
            return NoContent();
        }
        [Authorize]
        [HttpGet("GetUser")]
        public async Task<IActionResult> GetCurrentUser()
        {
            var email = User.FindFirst("Email")?.Value;

            if (string.IsNullOrEmpty(email))
            {
                return Unauthorized(new { message = "Invalid token or user not found." });
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);

            if (user == null)
            {
                return NotFound(new { message = "User not found." });
            }

            var userDetails = new
            {
                user.Id,
                user.Username,
                user.Email,
                user.CreatedAt,
                user.IsActive,
                user.LastLoginAt
            };

            return Ok(userDetails);
        }

        [Authorize]
        [HttpGet("GetUsers")]
        public async Task<IActionResult> GetUser([FromQuery] int id)
        {
            var user = await _context.Users.FindAsync(id);

            if (user == null)
            {
                return NotFound(new { message = "User not found." });
            }

            var userDetails = new
            {
                user.Id,
                user.Username,
                user.Email,
                user.CreatedAt,
                user.IsActive,
                user.LastLoginAt
            };

            return Ok(userDetails);
        }


    }
}
