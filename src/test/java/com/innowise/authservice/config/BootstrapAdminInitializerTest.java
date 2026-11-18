
package com.innowise.authservice.config;

import com.innowise.authservice.client.UserServiceClient;
import com.innowise.authservice.dto.response.UserServiceUserDetailsResponse;
import com.innowise.authservice.dto.response.UserServiceUserResponse;
import com.innowise.authservice.entity.Credential;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.repository.CredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.ApplicationArguments;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class BootstrapAdminInitializerTest {

    @Mock
    private CredentialRepository credentialRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private UserServiceClient userServiceClient;

    private ApplicationArguments args;

    @BeforeEach
    void setUp() {
        args = mock(ApplicationArguments.class);
    }

    private BootstrapAdminInitializer createInitializer(
            String username,
            String password,
            String name,
            String surname,
            String email
    ) {
        return new BootstrapAdminInitializer(
                credentialRepository,
                passwordEncoder,
                userServiceClient,
                username,
                password,
                name,
                surname,
                email
        );
    }

    private UserServiceUserDetailsResponse existingUser(Long id) {
        return new UserServiceUserDetailsResponse(
                id,
                "Admin",
                "Marketplace",
                null,
                "admin@marketplace.local",
                true,
                LocalDateTime.now(),
                LocalDateTime.now()
        );
    }

    @Test
    void shouldDoNothingWhenAllAdminPropertiesAreBlank() {
        var initializer = createInitializer("", "", "", "", "");

        assertDoesNotThrow(() -> initializer.run(args));

        verifyNoInteractions(
                credentialRepository,
                passwordEncoder,
                userServiceClient
        );
    }

    @Test
    void shouldThrowWhenOnlySomeAdminPropertiesAreConfigured() {
        var initializer = createInitializer(
                "admin", "", "Admin", "Marketplace",
                "admin@marketplace.local"
        );

        assertThrows(
                IllegalStateException.class,
                () -> initializer.run(args)
        );

        verifyNoInteractions(
                credentialRepository,
                passwordEncoder,
                userServiceClient
        );
    }

    @Test
    void shouldThrowWhenPasswordIsTooShort() {
        var initializer = createInitializer(
                "admin", "short", "Admin", "Marketplace",
                "admin@marketplace.local"
        );

        assertThrows(
                IllegalStateException.class,
                () -> initializer.run(args)
        );

        verifyNoInteractions(
                credentialRepository,
                passwordEncoder,
                userServiceClient
        );
    }

    @Test
    void shouldThrowWhenPasswordIsTooLong() {
        var initializer = createInitializer(
                "admin", "a".repeat(73), "Admin", "Marketplace",
                "admin@marketplace.local"
        );

        assertThrows(
                IllegalStateException.class,
                () -> initializer.run(args)
        );

        verifyNoInteractions(
                credentialRepository,
                passwordEncoder,
                userServiceClient
        );
    }

    @Test
    void shouldCreateAdminWhenProfileDoesNotExist() {
        var initializer = createInitializer(
                "admin", "password123", "Admin", "Marketplace",
                "admin@marketplace.local"
        );

        when(credentialRepository.findByUsername("admin"))
                .thenReturn(Optional.empty());

        when(userServiceClient.findUserByEmail("admin@marketplace.local"))
                .thenReturn(null);

        when(userServiceClient.createUser(any()))
                .thenReturn(new UserServiceUserResponse(42L));

        when(credentialRepository.findByUserId(42L))
                .thenReturn(Optional.empty());

        when(passwordEncoder.encode("password123"))
                .thenReturn("encoded-password");

        initializer.run(args);

        ArgumentCaptor<Credential> captor =
                ArgumentCaptor.forClass(Credential.class);

        verify(credentialRepository).saveAndFlush(captor.capture());

        Credential saved = captor.getValue();

        assertEquals(42L, saved.getUserId());
        assertEquals("admin", saved.getUsername());
        assertEquals("encoded-password", saved.getPasswordHash());
        assertEquals(Role.ADMIN, saved.getRole());

        verify(userServiceClient).createUser(any());
        verify(passwordEncoder).encode("password123");
    }

    @Test
    void shouldReuseExistingUserProfile() {
        var initializer = createInitializer(
                "admin", "password123", "Admin", "Marketplace",
                "admin@marketplace.local"
        );

        when(credentialRepository.findByUsername("admin"))
                .thenReturn(Optional.empty());

        when(userServiceClient.findUserByEmail("admin@marketplace.local"))
                .thenReturn(existingUser(42L));

        when(credentialRepository.findByUserId(42L))
                .thenReturn(Optional.empty());

        when(passwordEncoder.encode("password123"))
                .thenReturn("encoded-password");

        initializer.run(args);

        ArgumentCaptor<Credential> captor =
                ArgumentCaptor.forClass(Credential.class);

        verify(credentialRepository).saveAndFlush(captor.capture());

        assertEquals(42L, captor.getValue().getUserId());

        verify(userServiceClient, never()).createUser(any());
    }

    @Test
    void shouldThrowWhenProfileIdAlreadyBelongsToAnotherCredential() {
        var initializer = createInitializer(
                "admin", "password123", "Admin", "Marketplace",
                "admin@marketplace.local"
        );

        Credential anotherCredential = new Credential();
        anotherCredential.setUserId(42L);
        anotherCredential.setUsername("another-user");
        anotherCredential.setRole(Role.USER);

        when(credentialRepository.findByUsername("admin"))
                .thenReturn(Optional.empty());

        when(userServiceClient.findUserByEmail("admin@marketplace.local"))
                .thenReturn(existingUser(42L));

        when(credentialRepository.findByUserId(42L))
                .thenReturn(Optional.of(anotherCredential));

        assertThrows(
                IllegalStateException.class,
                () -> initializer.run(args)
        );

        verify(credentialRepository, never()).saveAndFlush(any());
    }

    @Test
    void shouldThrowWhenExistingUsernameBelongsToNonAdmin() {
        Credential existing = new Credential();
        existing.setUserId(42L);
        existing.setUsername("admin");
        existing.setRole(Role.USER);

        var initializer = createInitializer(
                "admin", "password123", "Admin", "Marketplace",
                "admin@marketplace.local"
        );

        when(credentialRepository.findByUsername("admin"))
                .thenReturn(Optional.of(existing));

        assertThrows(
                IllegalStateException.class,
                () -> initializer.run(args)
        );

        verifyNoInteractions(userServiceClient);
        verify(credentialRepository, never()).saveAndFlush(any());
    }

    @Test
    void shouldDoNothingWhenCorrectAdminAlreadyExists() {
        Credential existing = new Credential();
        existing.setUserId(42L);
        existing.setUsername("admin");
        existing.setRole(Role.ADMIN);

        var initializer = createInitializer(
                "admin", "password123", "Admin", "Marketplace",
                "admin@marketplace.local"
        );

        when(credentialRepository.findByUsername("admin"))
                .thenReturn(Optional.of(existing));

        when(userServiceClient.findUserByEmail("admin@marketplace.local"))
                .thenReturn(existingUser(42L));

        assertDoesNotThrow(() -> initializer.run(args));

        verify(credentialRepository, never()).saveAndFlush(any());
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void shouldThrowWhenExistingAdminProfileDoesNotMatchCredentials() {
        Credential existing = new Credential();
        existing.setUserId(42L);
        existing.setUsername("admin");
        existing.setRole(Role.ADMIN);

        var initializer = createInitializer(
                "admin", "password123", "Admin", "Marketplace",
                "admin@marketplace.local"
        );

        when(credentialRepository.findByUsername("admin"))
                .thenReturn(Optional.of(existing));

        when(userServiceClient.findUserByEmail("admin@marketplace.local"))
                .thenReturn(existingUser(99L));

        assertThrows(
                IllegalStateException.class,
                () -> initializer.run(args)
        );

        verify(credentialRepository, never()).saveAndFlush(any());
    }
}
