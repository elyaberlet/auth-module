
package com.innowise.authservice.service;

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
import com.innowise.authservice.service.impl.AuthServiceImpl;
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

import java.time.LocalDate;
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

    @Mock
    private UserServiceClient userServiceClient;

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
                "John",
                "Doe",
                LocalDate.of(1995, 5, 15),
                "john.doe@example.com",
                "testuser",
                "Password123"
        );
    }

    @Test
    void register_shouldCreateUserAndSaveCredential() {
        CreateCredentialRequest request = createCredentialRequest();

        UserServiceUserResponse userResponse =
                new UserServiceUserResponse(1001L);

        when(credentialRepository.existsByUsername("testuser"))
                .thenReturn(false);

        when(userServiceClient.createUser(
                any(UserServiceCreateUserRequest.class)
        )).thenReturn(userResponse);

        when(credentialMapper.toEntity(1001L, request))
                .thenReturn(credential);

        when(passwordEncoder.encode("Password123"))
                .thenReturn("encoded-password");

        when(credentialRepository.saveAndFlush(credential))
                .thenReturn(credential);

        when(credentialMapper.toRegisterResponse(credential))
                .thenReturn(new RegisterResponse(
                        1001L,
                        "testuser",
                        Role.USER
                ));

        RegisterResponse response = authService.register(request);

        assertEquals(1001L, response.userId());
        assertEquals("testuser", response.username());
        assertEquals(Role.USER, response.role());

        ArgumentCaptor<UserServiceCreateUserRequest> userRequestCaptor =
                ArgumentCaptor.forClass(UserServiceCreateUserRequest.class);

        verify(userServiceClient).createUser(userRequestCaptor.capture());

        UserServiceCreateUserRequest userRequest =
                userRequestCaptor.getValue();

        assertEquals("John", userRequest.name());
        assertEquals("Doe", userRequest.surname());
        assertEquals(LocalDate.of(1995, 5, 15), userRequest.birthDate());
        assertEquals("john.doe@example.com", userRequest.email());

        ArgumentCaptor<Credential> credentialCaptor =
                ArgumentCaptor.forClass(Credential.class);

        verify(credentialRepository).saveAndFlush(credentialCaptor.capture());

        Credential saved = credentialCaptor.getValue();

        assertEquals(1001L, saved.getUserId());
        assertEquals("testuser", saved.getUsername());
        assertEquals("encoded-password", saved.getPasswordHash());
        assertEquals(Role.USER, saved.getRole());

        verify(credentialMapper).toEntity(1001L, request);
        verify(passwordEncoder).encode("Password123");
        verify(credentialMapper).toRegisterResponse(credential);

        verify(userServiceClient, never()).deleteUser(anyLong());
    }

    @Test
    void register_shouldThrowWhenUsernameAlreadyExists() {
        CreateCredentialRequest request = createCredentialRequest();

        when(credentialRepository.existsByUsername("testuser"))
                .thenReturn(true);

        assertThrows(
                UsernameAlreadyExistsException.class,
                () -> authService.register(request)
        );

        verify(userServiceClient, never())
                .createUser(any(UserServiceCreateUserRequest.class));

        verify(credentialRepository, never())
                .saveAndFlush(any(Credential.class));

        verify(credentialMapper, never())
                .toEntity(anyLong(), any(CreateCredentialRequest.class));

        verify(passwordEncoder, never())
                .encode(anyString());
    }

    @Test
    void register_shouldDeleteUserWhenCredentialSaveFails() {
        CreateCredentialRequest request = createCredentialRequest();

        when(credentialRepository.existsByUsername("testuser"))
                .thenReturn(false);

        when(userServiceClient.createUser(
                any(UserServiceCreateUserRequest.class)
        )).thenReturn(new UserServiceUserResponse(1001L));

        when(credentialMapper.toEntity(1001L, request))
                .thenReturn(credential);

        when(passwordEncoder.encode("Password123"))
                .thenReturn("encoded-password");

        RuntimeException databaseException =
                new RuntimeException("Database error");

        when(credentialRepository.saveAndFlush(credential))
                .thenThrow(databaseException);

        RuntimeException thrown = assertThrows(
                RuntimeException.class,
                () -> authService.register(request)
        );

        assertSame(databaseException, thrown);

        verify(userServiceClient).deleteUser(1001L);
    }

    @Test
    void register_shouldKeepOriginalExceptionWhenCompensationFails() {
        CreateCredentialRequest request = createCredentialRequest();

        when(credentialRepository.existsByUsername("testuser"))
                .thenReturn(false);

        when(userServiceClient.createUser(
                any(UserServiceCreateUserRequest.class)
        )).thenReturn(new UserServiceUserResponse(1001L));

        when(credentialMapper.toEntity(1001L, request))
                .thenReturn(credential);

        when(passwordEncoder.encode("Password123"))
                .thenReturn("encoded-password");

        RuntimeException databaseException =
                new RuntimeException("Database error");

        RuntimeException compensationException =
                new RuntimeException("User Service deletion failed");

        when(credentialRepository.saveAndFlush(credential))
                .thenThrow(databaseException);

        doThrow(compensationException)
                .when(userServiceClient)
                .deleteUser(1001L);

        RuntimeException thrown = assertThrows(
                RuntimeException.class,
                () -> authService.register(request)
        );

        assertSame(databaseException, thrown);
        assertEquals(1, thrown.getSuppressed().length);
        assertSame(compensationException, thrown.getSuppressed()[0]);
    }

    @Test
    void register_shouldNotSaveCredentialWhenUserServiceReturnsInvalidId() {
        CreateCredentialRequest request = createCredentialRequest();

        when(credentialRepository.existsByUsername("testuser"))
                .thenReturn(false);

        when(userServiceClient.createUser(
                any(UserServiceCreateUserRequest.class)
        )).thenReturn(new UserServiceUserResponse(null));

        assertThrows(
                IllegalStateException.class,
                () -> authService.register(request)
        );

        verify(credentialRepository, never())
                .saveAndFlush(any(Credential.class));

        verify(credentialMapper, never())
                .toEntity(anyLong(), any(CreateCredentialRequest.class));

        verify(userServiceClient, never())
                .deleteUser(anyLong());
    }

    @Test
    void register_shouldNotSaveCredentialWhenUserServiceFails() {
        CreateCredentialRequest request = createCredentialRequest();

        when(credentialRepository.existsByUsername("testuser"))
                .thenReturn(false);

        when(userServiceClient.createUser(
                any(UserServiceCreateUserRequest.class)
        )).thenThrow(new RuntimeException("User Service unavailable"));

        assertThrows(
                RuntimeException.class,
                () -> authService.register(request)
        );

        verify(credentialRepository, never())
                .saveAndFlush(any(Credential.class));

        verify(credentialMapper, never())
                .toEntity(anyLong(), any(CreateCredentialRequest.class));
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

        when(credentialRepository.findByUserId(1001L))
                .thenReturn(Optional.of(credential));

        when(jwtService.generateAccessToken(1001L, Role.USER))
                .thenReturn("new-access-token");

        when(jwtService.generateRefreshToken(1001L, Role.USER))
                .thenReturn("new-refresh-token");

        TokenResponse response = authService.refresh(request);

        assertEquals("new-access-token", response.accessToken());
        assertEquals("new-refresh-token", response.refreshToken());
        assertEquals("Bearer", response.tokenType());

        verify(credentialRepository).findByUserId(1001L);
        verify(jwtService).generateAccessToken(1001L, Role.USER);
        verify(jwtService).generateRefreshToken(1001L, Role.USER);
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
    void refresh_shouldUseCurrentRoleFromDatabase() {
        RefreshTokenRequest request =
                new RefreshTokenRequest("old-refresh-token");

        Claims claims = mock(Claims.class);

        credential.setRole(Role.ADMIN);

        when(jwtService.validateRefreshToken("old-refresh-token"))
                .thenReturn(claims);

        when(claims.get("user_id", Long.class))
                .thenReturn(1001L);

        when(credentialRepository.findByUserId(1001L))
                .thenReturn(Optional.of(credential));

        when(jwtService.generateAccessToken(1001L, Role.ADMIN))
                .thenReturn("new-access-token");

        when(jwtService.generateRefreshToken(1001L, Role.ADMIN))
                .thenReturn("new-refresh-token");

        TokenResponse response = authService.refresh(request);

        assertEquals("new-access-token", response.accessToken());
        assertEquals("new-refresh-token", response.refreshToken());

        verify(jwtService).generateAccessToken(1001L, Role.ADMIN);
        verify(jwtService).generateRefreshToken(1001L, Role.ADMIN);
    }

    @Test
    void refresh_shouldThrowWhenCredentialDoesNotExist() {
        RefreshTokenRequest request =
                new RefreshTokenRequest("old-refresh-token");

        Claims claims = mock(Claims.class);

        when(jwtService.validateRefreshToken("old-refresh-token"))
                .thenReturn(claims);

        when(claims.get("user_id", Long.class))
                .thenReturn(1001L);

        when(credentialRepository.findByUserId(1001L))
                .thenReturn(Optional.empty());

        assertThrows(
                InvalidCredentialsException.class,
                () -> authService.refresh(request)
        );

        verify(jwtService, never())
                .generateAccessToken(anyLong(), any());

        verify(jwtService, never())
                .generateRefreshToken(anyLong(), any());
    }
}
