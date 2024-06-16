namespace UserServiceApi.Models
{

    public enum TypeAddress
    {

        Home = 1,


    }
    public class UserUpdateDto
    {
        public string Name { get; set; }

        public string Cpf { get; set; }

        public bool Active { get; set; }

        public string Email { get; set; }

        public Guid Id { get; set; }

        public string PublicPlace { get; set; }
        public string Number { get; set; }
        public string Complement { get; set; }
        public string ZipCode { get; set; }
        public string City { get; set; }
        public TypeAddress TypeAddress { get; set; }
        public string District { get; set; }
        public string State { get; set; }
    }
}
