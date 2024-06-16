using AutoMapper;
using Microsoft.AspNetCore.Identity;
using UserServiceApi.Models;

namespace UserServiceApi.AutoMapper
{
    public class RequestToResponseModelMappingProfile : Profile
    {
        public RequestToResponseModelMappingProfile()
        {
            CreateMap<UserRegisterRequest, UserRegisterDto>();
            CreateMap<UserUpdateRequest, UserUpdateDto>();
            CreateMap<IdentityUser, UserUpdateDto>();
            CreateMap<IdentityUser, UserRegisterDto>();

        }
    }
}
