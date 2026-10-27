package com.marketplace.authservice.service.impl;

import com.marketplace.authservice.dto.request.CreateCredentialRequest;
import com.marketplace.authservice.dto.request.LoginRequest;
import com.marketplace.authservice.dto.request.RefreshTokenRequest;
import com.marketplace.authservice.dto.request.ValidateTokenRequest;
import com.marketplace.authservice.dto.response.RegisterResponse;
import com.marketplace.authservice.dto.response.TokenResponse;
import com.marketplace.authservice.dto.response.ValidateTokenResponse;
import com.marketplace.authservice.entity.Credential;
import com.marketplace.authservice.entity.Role;
import com.marketplace.authservice.exception.InvalidCredentialsException;
import com.marketplace.authservice.exception.UsernameAlreadyExistsException;
import com.marketplace.authservice.mapper.CredentialMapper;
import com.marketplace.authservice.repository.CredentialRepository;
import com.marketplace.authservice.service.AuthService;
import com.marketplace.authservice.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthServiceImpl implements AuthService {

    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final CredentialMapper credentialMapper;

    public AuthServiceImpl(
            CredentialRepository credentialRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            CredentialMapper credentialMapper
    ) {
        this.credentialRepository = credentialRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.credentialMapper = credentialMapper;
    }

    @Override
    @Transactional
    public RegisterResponse createCredential(CreateCredentialRequest request) {
        if (credentialRepository.existsByUsername(request.username())) {
            throw new UsernameAlreadyExistsException(request.username());
        }

        Credential credential = credentialMapper.toEntity(request);

        credential.setPasswordHash(
                passwordEncoder.encode(request.password())
        );

        Credential savedCredential = credentialRepository.save(credential);

        return credentialMapper.toRegisterResponse(savedCredential);
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
        Role role = Role.valueOf(claims.get("role", String.class));

        String accessToken = jwtService.generateAccessToken(userId, role);
        String refreshToken = jwtService.generateRefreshToken(userId, role);

        return new TokenResponse(accessToken, refreshToken, "Bearer");
    }

    @Override
    public ValidateTokenResponse validateToken(ValidateTokenRequest request) {
        try {
            Claims claims = jwtService.validateAccessToken(
                    request.accessToken()
            );

            Long userId = claims.get("user_id", Long.class);
            String roleValue = claims.get("role", String.class);

            if (userId == null || userId <= 0 || roleValue == null) {
                return new ValidateTokenResponse(false, null, null);
            }

            Role role = Role.valueOf(roleValue);

            return new ValidateTokenResponse(
                    true,
                    userId,
                    role.name()
            );

        } catch (JwtException | IllegalArgumentException exception) {
            return new ValidateTokenResponse(false, null, null);
        }
    }
}
