package com.innowise.authservice.mapper;

import com.innowise.authservice.dto.request.CreateCredentialRequest;
import com.innowise.authservice.dto.response.RegisterResponse;
import com.innowise.authservice.entity.Credential;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface CredentialMapper {

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "userId", source = "userId")
    @Mapping(target = "passwordHash", ignore = true)
    @Mapping(
            target = "role",
            expression = "java(com.innowise.authservice.entity.Role.USER)"
    )
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    Credential toEntity(Long userId, CreateCredentialRequest request);

    RegisterResponse toRegisterResponse(Credential credential);
}
