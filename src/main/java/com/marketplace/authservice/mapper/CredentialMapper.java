package com.marketplace.authservice.mapper;

import com.marketplace.authservice.dto.request.CreateCredentialRequest;
import com.marketplace.authservice.dto.response.RegisterResponse;
import com.marketplace.authservice.entity.Credential;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface CredentialMapper {

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "passwordHash", ignore = true)
    @Mapping(target = "role", expression = "java(Role.USER)")
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    Credential toEntity(CreateCredentialRequest request);

    RegisterResponse toRegisterResponse(Credential credential);
}
