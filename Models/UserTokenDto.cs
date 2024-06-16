namespace UserServiceApi.Models
{
    public class UserTokenDto
    {
        public string Id { get; set; }
        public string Email { get; set; }
        public IEnumerable<UserClaimDto> Claims { get; set; }
        public string Name { get; set; }

        public UserTokenDto()
        {
            Claims = new List<UserClaimDto>();
        }
    }
}
