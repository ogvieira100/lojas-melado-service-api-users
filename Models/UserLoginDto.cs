namespace UserServiceApi.Models
{
    public class UserLoginDto
    {
        public string AccessToken { get; set; }
        public double ExpiresIn { get; set; }
        public UserTokenDto UserToken { get; set; }
        public Guid RefreshToken { get; set; }
    }
}
