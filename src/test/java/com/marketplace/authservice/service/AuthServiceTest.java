package com.marketplace.authservice.service;

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
import com.marketplace.authservice.service.impl.AuthServiceImpl;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private CredentialRepository credentialRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private CredentialMapper credentialMapper;

    @InjectMocks
    private AuthServiceImpl authService;

    private Credential credential;

    @BeforeEach
    void setUp() {
        credential = new Credential();
        credential.setUserId(1001L);
        credential.setUsername("testuser");
        credential.setPasswordHash("encoded-password");
        credential.setRole(Role.USER);
    }

    private CreateCredentialRequest createCredentialRequest() {
        return new CreateCredentialRequest(
                1001L,
                "testuser",
                "Password123"
        );
    }

    @Test
    void createCredential_shouldSaveCredentialAndReturnResponse() {
        CreateCredentialRequest request = createCredentialRequest();

        when(credentialRepository.existsByUsername("testuser"))
                .thenReturn(false);

        when(credentialMapper.toEntity(request))
                .thenReturn(credential);

        when(passwordEncoder.encode("Password123"))
                .thenReturn("encoded-password");

        when(credentialRepository.save(any(Credential.class)))
                .thenReturn(credential);

        when(credentialMapper.toRegisterResponse(credential))
                .thenReturn(new RegisterResponse(
                        1001L,
                        "testuser",
                        Role.USER
                ));

        RegisterResponse response = authService.createCredential(request);

        assertEquals(1001L, response.userId());
        assertEquals("testuser", response.username());
        assertEquals(Role.USER, response.role());

        ArgumentCaptor<Credential> credentialCaptor =
                ArgumentCaptor.forClass(Credential.class);

        verify(credentialRepository).save(credentialCaptor.capture());

        Credential saved = credentialCaptor.getValue();

        assertEquals(1001L, saved.getUserId());
        assertEquals("testuser", saved.getUsername());
        assertEquals("encoded-password", saved.getPasswordHash());
        assertEquals(Role.USER, saved.getRole());

        verify(credentialMapper).toEntity(request);
        verify(passwordEncoder).encode("Password123");
        verify(credentialMapper).toRegisterResponse(credential);
    }

    @Test
    void createCredential_shouldThrowWhenUsernameAlreadyExists() {
        CreateCredentialRequest request = createCredentialRequest();

        when(credentialRepository.existsByUsername("testuser"))
                .thenReturn(true);

        assertThrows(
                UsernameAlreadyExistsException.class,
                () -> authService.createCredential(request)
        );

        verify(credentialRepository, never())
                .save(any(Credential.class));

        verify(credentialMapper, never())
                .toEntity(any(CreateCredentialRequest.class));

        verify(passwordEncoder, never())
                .encode(anyString());
    }

    @Test
    void login_shouldReturnTokensWhenCredentialsAreCorrect() {
        LoginRequest request =
                new LoginRequest("testuser", "Password123");

        when(credentialRepository.findByUsername("testuser"))
                .thenReturn(Optional.of(credential));

        when(passwordEncoder.matches(
                "Password123",
                "encoded-password"
        )).thenReturn(true);

        when(jwtService.generateAccessToken(1001L, Role.USER))
                .thenReturn("access-token");

        when(jwtService.generateRefreshToken(1001L, Role.USER))
                .thenReturn("refresh-token");

        TokenResponse response = authService.login(request);

        assertEquals("access-token", response.accessToken());
        assertEquals("refresh-token", response.refreshToken());
        assertEquals("Bearer", response.tokenType());

        verify(jwtService).generateAccessToken(1001L, Role.USER);
        verify(jwtService).generateRefreshToken(1001L, Role.USER);
    }

    @Test
    void login_shouldThrowWhenUsernameDoesNotExist() {
        LoginRequest request =
                new LoginRequest("unknown", "Password123");

        when(credentialRepository.findByUsername("unknown"))
                .thenReturn(Optional.empty());

        assertThrows(
                InvalidCredentialsException.class,
                () -> authService.login(request)
        );

        verify(passwordEncoder, never())
                .matches(anyString(), anyString());

        verify(jwtService, never())
                .generateAccessToken(any(), any());
    }

    @Test
    void login_shouldThrowWhenPasswordIsIncorrect() {
        LoginRequest request =
                new LoginRequest("testuser", "WrongPassword");

        when(credentialRepository.findByUsername("testuser"))
                .thenReturn(Optional.of(credential));

        when(passwordEncoder.matches(
                "WrongPassword",
                "encoded-password"
        )).thenReturn(false);

        assertThrows(
                InvalidCredentialsException.class,
                () -> authService.login(request)
        );

        verify(jwtService, never())
                .generateAccessToken(any(), any());

        verify(jwtService, never())
                .generateRefreshToken(any(), any());
    }

    @Test
    void refresh_shouldReturnNewTokenPair() {
        RefreshTokenRequest request =
                new RefreshTokenRequest("old-refresh-token");

        Claims claims = mock(Claims.class);

        when(jwtService.validateRefreshToken("old-refresh-token"))
                .thenReturn(claims);

        when(claims.get("user_id", Long.class))
                .thenReturn(1001L);

        when(claims.get("role", String.class))
                .thenReturn("USER");

        when(jwtService.generateAccessToken(1001L, Role.USER))
                .thenReturn("new-access-token");

        when(jwtService.generateRefreshToken(1001L, Role.USER))
                .thenReturn("new-refresh-token");

        TokenResponse response = authService.refresh(request);

        assertEquals("new-access-token", response.accessToken());
        assertEquals("new-refresh-token", response.refreshToken());
        assertEquals("Bearer", response.tokenType());
    }

    @Test
    void refresh_shouldPropagateExceptionForInvalidRefreshToken() {
        RefreshTokenRequest request =
                new RefreshTokenRequest("invalid-token");

        when(jwtService.validateRefreshToken("invalid-token"))
                .thenThrow(new JwtException("Invalid token"));

        assertThrows(
                JwtException.class,
                () -> authService.refresh(request)
        );

        verify(jwtService, never())
                .generateAccessToken(any(), any());

        verify(jwtService, never())
                .generateRefreshToken(any(), any());
    }

    @Test
    void validateToken_shouldReturnValidWhenClaimsArePresent() {
        ValidateTokenRequest request =
                new ValidateTokenRequest("valid-access-token");

        Claims claims = mock(Claims.class);

        when(jwtService.validateAccessToken("valid-access-token"))
                .thenReturn(claims);

        when(claims.get("user_id", Long.class))
                .thenReturn(1001L);

        when(claims.get("role", String.class))
                .thenReturn("USER");

        ValidateTokenResponse response =
                authService.validateToken(request);

        assertTrue(response.valid());
        assertEquals(1001L, response.userId());
        assertEquals("USER", response.role());
    }

    @Test
    void validateToken_shouldReturnInvalidWhenUserIdIsMissing() {
        ValidateTokenRequest request =
                new ValidateTokenRequest("token-without-user-id");

        Claims claims = mock(Claims.class);

        when(jwtService.validateAccessToken("token-without-user-id"))
                .thenReturn(claims);

        when(claims.get("user_id", Long.class))
                .thenReturn(null);

        when(claims.get("role", String.class))
                .thenReturn("USER");

        ValidateTokenResponse response =
                authService.validateToken(request);

        assertFalse(response.valid());
        assertNull(response.userId());
        assertNull(response.role());
    }

    @Test
    void validateToken_shouldReturnInvalidWhenJwtThrowsException() {
        ValidateTokenRequest request =
                new ValidateTokenRequest("invalid-access-token");

        when(jwtService.validateAccessToken("invalid-access-token"))
                .thenThrow(new JwtException("Invalid token"));

        ValidateTokenResponse response =
                authService.validateToken(request);

        assertFalse(response.valid());
        assertNull(response.userId());
        assertNull(response.role());
    }
}
