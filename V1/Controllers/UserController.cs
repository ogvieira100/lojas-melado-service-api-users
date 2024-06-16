using Asp.Versioning;
using AutoMapper;
using buildingBlocksCore.Identity;
using buildingBlocksCore.Mediator.Messages.Integration;
using buildingBlocksCore.Utils;
using BuildingBlocksMessageBus.Interfaces;
using BuildingBlocksServices.Controllers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Core.Interfaces;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using userApi.Models;
using UserServiceApi.Data;
using UserServiceApi.Models;

namespace UserServiceApi.V1.Controllers
{

    [ApiVersion("1.0")]
    [Route("api/v{version:apiVersion}/user")]
    [Authorize]
    public class UserController : MainController
    {

        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly AppSettings _appSettings;
        readonly AppTokenSettings _appTokenSettings;
        readonly IPasswordHasher<IdentityUser> _passwordHasher;
        readonly IUser _user;
        readonly ApplicationUserRefreshSecurityContext _applicationUserContext;
        readonly IJwtService _jsonWebKeySetService;
        readonly IMapper _mapper;
        readonly IMessageBusRabbitMq _messageBusRabbitMq;
        readonly ILogger<UserController> _logger;

        public UserController(SignInManager<IdentityUser> signInManager,
                               UserManager<IdentityUser> userManager,
                               IOptions<AppSettings> appSettings,
                               ILogger<UserController> logger,
                               IOptions<AppTokenSettings> appTokenSettings,
                               IMapper mapper,
                               IMessageBusRabbitMq messageBusRabbitMq,
                               ApplicationUserRefreshSecurityContext applicationUserContext,
                               IJwtService jsonWebKeySetService,
                               IUser user,
                               IPasswordHasher<IdentityUser> passwordHasher,
                               LNotifications notifications)
         : base(notifications)
        {
            _appTokenSettings = appTokenSettings.Value;
            _user = user;
            _logger = logger;
            _messageBusRabbitMq = messageBusRabbitMq;
            _mapper = mapper;
            _applicationUserContext = applicationUserContext;
            _signInManager = signInManager;
            _userManager = userManager;
            _appSettings = appSettings.Value;
            _passwordHasher = passwordHasher;
            _jsonWebKeySetService = jsonWebKeySetService;
        }


        [HttpPut("atualizar-conta")]
        [ClaimsAuthorize("UsersAdm", "1")]
        public async Task<IActionResult> UpdateAccount([FromBody] UserUpdateRequest userUpdate)
        {
            if (!ModelState.IsValid) return ReturnModelState(ModelState);
            return await ExecControllerAsync(async () =>
            {
                var user = await _userManager.FindByIdAsync(userUpdate.Id.ToString());

                if (user == null)
                {
                    ModelState.AddModelError("", "Usuário não Encontado");
                    NotifyModelStateErrors();
                    return null;
                }

                user.Email = userUpdate.Email;
                // user.PasswordHash = _passwordHasher.HashPassword(user, userUpdate.Password);
                IdentityResult result = await _userManager.UpdateAsync(user);
                if (result.Succeeded)
                    return _mapper.Map<UserUpdateDto>(user);
                else
                {
                    AddError(result);
                }
                return null;
            });
        }


        [HttpDelete("deletar-conta/{id:guid}")]
        [ClaimsAuthorize("UsersAdm", "1")]
        public async Task<IActionResult> DeleteAccount([FromRoute] Guid id)
        {

            return await ExecControllerAsync(async () =>
            {
                var identityUser = await _userManager.FindByIdAsync(id.ToString());
                if (identityUser != null)
                {
                    IdentityResult result = await _userManager.DeleteAsync(identityUser);
                    if (result.Succeeded)
                    {

                        _messageBusRabbitMq.Publish(new UserDeletedIntegrationEvent() { Id = id, UserDeleteId = id, Aplicacao = Aplicacao.Customer },
                        new BuildingBlocksMessageBus.Models.PropsMessageQueeDto
                        {
                            Queue = "QueeUserDeleted"
                        });
                        return new UserDeleteDto();
                    }
                    else
                    {
                        AddError(result);
                    }
                    return (null);
                }
                else
                {
                    ModelState.AddModelError("", "Usuário não Encontado");
                    NotifyModelStateErrors();
                }
                return (null);
            });
        }




        [HttpGet("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromQuery] UserLoginRequest userLogin)
        {
            if (!ModelState.IsValid) return ReturnModelState(ModelState);

            return await ExecControllerAsync(async () =>
            {
                var result = await _signInManager.PasswordSignInAsync(userLogin.Email, userLogin.Password,
                false, true);

                if (result.Succeeded)
                {
                    return await GenerateJwt(userLogin.Email);
                }

                if (result.IsLockedOut)
                {
                    AddError(new LNotification { Message = "Usuário temporariamente bloqueado por tentativas inválidas" });
                    return null;
                }

                AddError(new LNotification { Message = "Usuário ou Senha incorretos" });
                return null;
            });
        }




        [HttpPost("nova-conta")]
        //[AllowAnonymous]
        [ClaimsAuthorize("UsersAdm", "1")]

        public async Task<IActionResult> Register([FromBody] UserRegisterRequest userRegister)
        {

            if (!ModelState.IsValid) return ReturnModelState(ModelState);

            var registerGuid = Guid.NewGuid();

            _logger.Logar(new LogClass
            {

                Aplicacao = Aplicacao.User,
                EstadoProcesso = EstadoProcesso.Inicio,
                ProcessoId = registerGuid,
                TipoLog = TipoLog.Informacao,
                Processo = Processo.InserirUsuario,
                Msg = " Atenção Inicio do processo de registro de usuario "
            });

            return await ExecControllerAsync(async () =>
            {
                var user = new IdentityUser
                {
                    UserName = userRegister.Email,
                    Email = userRegister.Email,
                    EmailConfirmed = true

                };

                var result = await _userManager.CreateAsync(user, userRegister.Password);


                if (result.Succeeded)
                {


                    _logger.Logar(new LogClass
                    {
                        Aplicacao = Aplicacao.User,
                        EstadoProcesso = EstadoProcesso.Inicio,
                        ProcessoId = registerGuid,
                        TipoLog = TipoLog.Informacao,
                        Processo = Processo.InserirUsuario,
                        Msg = " Processo obteve sucesso preparando para enviar para o dominio de customer"
                    });

                    var response = _messageBusRabbitMq.RpcSendRequestReceiveResponse<UserInsertedIntegrationEvent, buildingBlocksCore.Mediator.Messages.ResponseMessage>(
                        new UserInsertedIntegrationEvent()
                        {

                            CPF = userRegister.CPF,
                            Email = userRegister.Email,
                            Name = userRegister.Name,
                            UserId = new Guid(user.Id.ToLower()),
                            UserInserted = _user.GetUserId(),
                            Aplicacao = Aplicacao.Customer,
                            ProcessoId = registerGuid,
                            Processo = Processo.InserirUsuario
                        }, new BuildingBlocksMessageBus.Models.PropsMessageQueeDto { Queue = "RPCUserInserted", Durable = false });
                    if (response.Notifications.Any())
                    {
                        _logger.Logar(new LogClass
                        {

                            Aplicacao = Aplicacao.User,
                            EstadoProcesso = EstadoProcesso.Inicio,
                            ProcessoId = registerGuid,
                            TipoLog = TipoLog.Erro,
                            Processo = Processo.InserirUsuario,
                            EObjetoJson = true,
                            Msg = JsonConvert.SerializeObject(response.Notifications)
                        });

                        _logger.Logar(new LogClass
                        {
                            Aplicacao = Aplicacao.User,
                            EstadoProcesso = EstadoProcesso.Inicio,
                            ProcessoId = registerGuid,
                            TipoLog = TipoLog.Informacao,
                            Processo = Processo.InserirUsuario,
                            Msg = " Deletando usuário da tabela de user "
                        });

                        await _userManager.DeleteAsync(user);
                        _notifications.AddRange(response.Notifications);
                        return (null);
                    }

                    _logger.Logar(new LogClass
                    {

                        Aplicacao = Aplicacao.User,
                        EstadoProcesso = EstadoProcesso.Finalizando,
                        ProcessoId = registerGuid,
                        TipoLog = TipoLog.Informacao,
                        Processo = Processo.InserirUsuario,
                        Msg = " Tudo certo finalizei "

                    });

                    return (_mapper.Map<UserRegisterDto>(user));
                }

                foreach (var error in result.Errors)
                {
                    AddError(new LNotification { Message = error.Description });
                }
                return (null);
            });
        }


        [HttpPost("refresh-token")]
        public async Task<IActionResult> GetRefreshToken([FromBody] string guid)
        {

            return await ExecControllerAsync(async () =>
            {

                if (!Guid.TryParse(guid, out var guidOut))
                {
                    AddError(new LNotification { Message = "Refresh Token Inválido" });
                    return (null);
                }

                var refreshToken = await GetRefreshToken(guidOut);

                if (refreshToken is null)
                {
                    AddError(new LNotification { Message = "Refresh Token Expirado" });
                    return (null);
                }
                return await GenerateJwt(guid);

            });
        }


        async Task<RefreshToken> GenerateRefreshToken(string email)
        {
            var refreshToken = new
                    RefreshToken()
            {
                UserName = email,
                ExpirationDate = DateTime.Now.AddHours(_appTokenSettings.RefreshTokenExpiration)
            };
            var refreshTokenDelete = await _applicationUserContext.RefreshTokens.Where(x => x.UserName == email).ToListAsync();
            foreach (var item in refreshTokenDelete)
            {
                _applicationUserContext.RefreshTokens.Remove(refreshToken);
            }

            //  _applicationUserContext.RefreshTokens.RemoveRange(refreshTokenDelete);
            await _applicationUserContext.RefreshTokens.AddAsync(refreshToken);
            await _applicationUserContext.SaveChangesAsync();
            return refreshToken;

        }
        async Task<UserLoginDto> GenerateJwt(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            var claims = await _userManager.GetClaimsAsync(user);

            var listClains = await GetClaimsUser(claims, user);
            var encodedToken = await GenerateJwt(roles: new List<string>(), addclaims: listClains.ToList(), user.Id, user.Email);
            var refreshToken = await GenerateRefreshToken(email);
            return GetResponseToken(encodedToken, user, claims, refreshToken.Token);
        }
        async Task<string> GenerateJwt(List<string> roles, List<Claim> addclaims, string userId, string email)
        {

            if (addclaims == null)
                addclaims = new List<Claim>();

            if (!string.IsNullOrEmpty(userId) && !addclaims.Any(x => x.Type == JwtRegisteredClaimNames.Sub))
                addclaims.Add(new Claim(JwtRegisteredClaimNames.Sub, userId));
            if (!string.IsNullOrEmpty(email) && !addclaims.Any(x => x.Type == JwtRegisteredClaimNames.Email))
                addclaims.Add(new Claim(JwtRegisteredClaimNames.Email, email));

            foreach (var role in roles)
                addclaims.Add(new Claim(ClaimTypes.Role, role));


            var identityClaims = new ClaimsIdentity();
            identityClaims.AddClaims(addclaims);

            var tokenHandler = new JwtSecurityTokenHandler();
            //var key = Encoding.ASCII.GetBytes("");
            var key = await _jsonWebKeySetService.GetCurrentSigningCredentials();
            var currentUser = $"{_user.GetHttpContext().Request.Scheme}://{_user.GetHttpContext().Request.Host}";

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identityClaims,
                Issuer = currentUser,
                Expires = DateTime.UtcNow.AddHours(1),/*expiração em 1hora vamos implementar refresh token */
                SigningCredentials = key
                //esse some 
                // SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            return tokenHandler.WriteToken(tokenHandler.CreateToken(tokenDescriptor));
        }
        async Task<IEnumerable<Claim>> GetClaimsUser(ICollection<Claim> claims, IdentityUser user)
        {
            var userRoles = await _userManager.GetRolesAsync(user);

            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
            claims.Add(new Claim(JwtRegisteredClaimNames.NameId, user.Id));
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, ToUnixEpochDate(DateTime.UtcNow).ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(DateTime.UtcNow).ToString(), ClaimValueTypes.Integer64));
            foreach (var userRole in userRoles)
            {
                claims.Add(new Claim("role", userRole));
            }

            return claims;
        }
        UserLoginDto GetResponseToken(string encodedToken, IdentityUser user, IEnumerable<Claim> claims, Guid refreshToken)
        {
            return new UserLoginDto
            {
                RefreshToken = refreshToken,
                AccessToken = encodedToken,
                ExpiresIn = TimeSpan.FromHours(1).TotalSeconds,
                UserToken = new UserTokenDto
                {
                    Id = user.Id,
                    Email = user.Email ?? "",
                    Name = user.NormalizedUserName ?? "",
                    Claims = claims.Select(c => new UserClaimDto { Type = c.Type, Value = c.Value })
                }
            };
        }

        async Task<RefreshToken?> GetRefreshToken(Guid refreshToken)
        {
            var token = await _applicationUserContext.RefreshTokens.AsNoTracking().FirstOrDefaultAsync(x => x.Token == refreshToken);
            return token != null && token.ExpirationDate > DateTime.Now ? token : null;
        }

        private static long ToUnixEpochDate(DateTime date)
            => (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);

    }
}
