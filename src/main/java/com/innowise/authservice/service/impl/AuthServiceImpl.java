package com.innowise.authservice.service.impl;

import com.innowise.authservice.client.UserServiceClient;
import com.innowise.authservice.dto.request.CreateCredentialRequest;
import com.innowise.authservice.dto.request.LoginRequest;
import com.innowise.authservice.dto.request.RefreshTokenRequest;
import com.innowise.authservice.dto.request.UserServiceCreateUserRequest;
import com.innowise.authservice.dto.response.RegisterResponse;
import com.innowise.authservice.dto.response.TokenResponse;
import com.innowise.authservice.dto.response.UserServiceUserResponse;
import com.innowise.authservice.entity.Credential;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.exception.InvalidCredentialsException;
import com.innowise.authservice.exception.UsernameAlreadyExistsException;
import com.innowise.authservice.mapper.CredentialMapper;
import com.innowise.authservice.repository.CredentialRepository;
import com.innowise.authservice.service.AuthService;
import com.innowise.authservice.service.JwtService;
import io.jsonwebtoken.Claims;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthServiceImpl implements AuthService {

    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final CredentialMapper credentialMapper;
    private final UserServiceClient userServiceClient;

    public AuthServiceImpl(
            CredentialRepository credentialRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            CredentialMapper credentialMapper,
            UserServiceClient userServiceClient
    ) {
        this.credentialRepository = credentialRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.credentialMapper = credentialMapper;
        this.userServiceClient = userServiceClient;
    }

    @Override
    @Transactional
    public RegisterResponse register(CreateCredentialRequest request) {
        if (credentialRepository.existsByUsername(request.username())) {
            throw new UsernameAlreadyExistsException(request.username());
        }

        UserServiceCreateUserRequest userRequest =
                new UserServiceCreateUserRequest(
                        request.name(),
                        request.surname(),
                        request.birthDate(),
                        request.email()
                );

        UserServiceUserResponse userResponse =
                userServiceClient.createUser(userRequest);

        if (userResponse == null
                || userResponse.id() == null
                || userResponse.id() <= 0) {
            throw new IllegalStateException(
                    "User Service returned an invalid user ID"
            );
        }

        Long userId = userResponse.id();

        try {
            Credential credential = credentialMapper.toEntity(
                    userId,
                    request
            );

            credential.setPasswordHash(
                    passwordEncoder.encode(request.password())
            );

            Credential savedCredential =
                    credentialRepository.saveAndFlush(credential);

            return credentialMapper.toRegisterResponse(savedCredential);

        } catch (RuntimeException exception) {
            try {
                userServiceClient.deleteUser(userId);
            } catch (RuntimeException compensationException) {
                exception.addSuppressed(compensationException);
            }

            throw exception;
        }
    }

    @Override
    public TokenResponse login(LoginRequest request) {
        Credential credential = credentialRepository
                .findByUsername(request.username())
                .orElseThrow(InvalidCredentialsException::new);

        if (!passwordEncoder.matches(
                request.password(),
                credential.getPasswordHash()
        )) {
            throw new InvalidCredentialsException();
        }

        String accessToken = jwtService.generateAccessToken(
                credential.getUserId(),
                credential.getRole()
        );

        String refreshToken = jwtService.generateRefreshToken(
                credential.getUserId(),
                credential.getRole()
        );

        return new TokenResponse(accessToken, refreshToken, "Bearer");
    }

    @Override
    public TokenResponse refresh(RefreshTokenRequest request) {
        Claims claims = jwtService.validateRefreshToken(
                request.refreshToken()
        );

        Long userId = claims.get("user_id", Long.class);

        if (userId == null || userId <= 0) {
            throw new InvalidCredentialsException();
        }

        Credential credential = credentialRepository
                .findByUserId(userId)
                .orElseThrow(InvalidCredentialsException::new);

        Role currentRole = credential.getRole();

        String accessToken = jwtService.generateAccessToken(
                credential.getUserId(),
                currentRole
        );

        String refreshToken = jwtService.generateRefreshToken(
                credential.getUserId(),
                currentRole
        );

        return new TokenResponse(accessToken, refreshToken, "Bearer");
    }
}