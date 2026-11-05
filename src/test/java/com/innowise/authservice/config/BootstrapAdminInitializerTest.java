
package com.innowise.authservice.config;

import com.innowise.authservice.entity.Credential;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.repository.CredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.ApplicationArguments;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class BootstrapAdminInitializerTest {

    @Mock
    private CredentialRepository credentialRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    private ApplicationArguments args;

    @BeforeEach
    void setUp() {
        args = mock(ApplicationArguments.class);
    }

    private BootstrapAdminInitializer createInitializer(
            String username,
            String password,
            String userId
    ) {
        return new BootstrapAdminInitializer(
                credentialRepository,
                passwordEncoder,
                username,
                password,
                userId
        );
    }

    @Test
    void shouldDoNothingWhenAllAdminPropertiesAreBlank() {
        BootstrapAdminInitializer initializer =
                createInitializer("", "", "");

        assertDoesNotThrow(() -> initializer.run(args));

        verifyNoInteractions(credentialRepository, passwordEncoder);
    }

    @Test
    void shouldThrowWhenOnlySomeAdminPropertiesAreConfigured() {
        BootstrapAdminInitializer initializer =
                createInitializer("admin", "", "1");

        assertThrows(
                IllegalStateException.class,
                () -> initializer.run(args)
        );

        verifyNoInteractions(credentialRepository, passwordEncoder);
    }

    @Test
    void shouldThrowWhenPasswordIsTooShort() {
        BootstrapAdminInitializer initializer =
                createInitializer("admin", "short", "1");

        assertThrows(
                IllegalStateException.class,
                () -> initializer.run(args)
        );

        verifyNoInteractions(credentialRepository, passwordEncoder);
    }

    @Test
    void shouldThrowWhenPasswordIsTooLong() {
        BootstrapAdminInitializer initializer =
                createInitializer("admin", "a".repeat(73), "1");

        assertThrows(
                IllegalStateException.class,
                () -> initializer.run(args)
        );

        verifyNoInteractions(credentialRepository, passwordEncoder);
    }

    @Test
    void shouldAcceptPasswordWithMinimumLength() {
        BootstrapAdminInitializer initializer =
                createInitializer("admin", "12345678", "1");

        when(credentialRepository.findByUsername("admin"))
                .thenReturn(Optional.empty());
        when(credentialRepository.findByUserId(1L))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode("12345678"))
                .thenReturn("encoded-password");

        assertDoesNotThrow(() -> initializer.run(args));

        verify(credentialRepository).save(any(Credential.class));
    }

    @Test
    void shouldAcceptPasswordWithMaximumLength() {
        String password = "a".repeat(72);

        BootstrapAdminInitializer initializer =
                createInitializer("admin", password, "1");

        when(credentialRepository.findByUsername("admin"))
                .thenReturn(Optional.empty());
        when(credentialRepository.findByUserId(1L))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode(password))
                .thenReturn("encoded-password");

        assertDoesNotThrow(() -> initializer.run(args));

        verify(credentialRepository).save(any(Credential.class));
    }

    @Test
    void shouldThrowWhenUserIdIsNotANumber() {
        BootstrapAdminInitializer initializer =
                createInitializer("admin", "password123", "abc");

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> initializer.run(args)
        );

        assertEquals(
                "ADMIN_USER_ID must be a valid number",
                exception.getMessage()
        );

        verifyNoInteractions(credentialRepository, passwordEncoder);
    }

    @Test
    void shouldThrowWhenUserIdIsZero() {
        BootstrapAdminInitializer initializer =
                createInitializer("admin", "password123", "0");

        assertThrows(
                IllegalStateException.class,
                () -> initializer.run(args)
        );

        verifyNoInteractions(credentialRepository, passwordEncoder);
    }

    @Test
    void shouldThrowWhenUserIdIsNegative() {
        BootstrapAdminInitializer initializer =
                createInitializer("admin", "password123", "-1");

        assertThrows(
                IllegalStateException.class,
                () -> initializer.run(args)
        );

        verifyNoInteractions(credentialRepository, passwordEncoder);
    }

    @Test
    void shouldThrowWhenUsernameBelongsToAnotherAccount() {
        Credential existing = new Credential();
        existing.setUserId(2L);
        existing.setRole(Role.ADMIN);

        BootstrapAdminInitializer initializer =
                createInitializer("admin", "password123", "1");

        when(credentialRepository.findByUsername("admin"))
                .thenReturn(Optional.of(existing));

        assertThrows(
                IllegalStateException.class,
                () -> initializer.run(args)
        );

        verify(credentialRepository, never()).findByUserId(anyLong());
        verify(credentialRepository, never()).save(any());
    }

    @Test
    void shouldThrowWhenUsernameBelongsToNonAdminAccount() {
        Credential existing = new Credential();
        existing.setUserId(1L);
        existing.setRole(Role.USER);

        BootstrapAdminInitializer initializer =
                createInitializer("admin", "password123", "1");

        when(credentialRepository.findByUsername("admin"))
                .thenReturn(Optional.of(existing));

        assertThrows(
                IllegalStateException.class,
                () -> initializer.run(args)
        );

        verify(credentialRepository, never()).findByUserId(anyLong());
        verify(credentialRepository, never()).save(any());
    }

    @Test
    void shouldThrowWhenUserIdBelongsToAnotherUsername() {
        Credential existing = new Credential();
        existing.setUserId(1L);
        existing.setUsername("another-user");
        existing.setRole(Role.ADMIN);

        BootstrapAdminInitializer initializer =
                createInitializer("admin", "password123", "1");

        when(credentialRepository.findByUsername("admin"))
                .thenReturn(Optional.empty());
        when(credentialRepository.findByUserId(1L))
                .thenReturn(Optional.of(existing));

        assertThrows(
                IllegalStateException.class,
                () -> initializer.run(args)
        );

        verify(credentialRepository, never()).save(any());
    }

    @Test
    void shouldThrowWhenUserIdBelongsToNonAdminAccount() {
        Credential existing = new Credential();
        existing.setUserId(1L);
        existing.setUsername("admin");
        existing.setRole(Role.USER);

        BootstrapAdminInitializer initializer =
                createInitializer("admin", "password123", "1");

        when(credentialRepository.findByUsername("admin"))
                .thenReturn(Optional.empty());
        when(credentialRepository.findByUserId(1L))
                .thenReturn(Optional.of(existing));

        assertThrows(
                IllegalStateException.class,
                () -> initializer.run(args)
        );

        verify(credentialRepository, never()).save(any());
    }

    @Test
    void shouldDoNothingWhenCorrectAdminAlreadyExists() {
        Credential existing = new Credential();
        existing.setUserId(1L);
        existing.setUsername("admin");
        existing.setRole(Role.ADMIN);

        BootstrapAdminInitializer initializer =
                createInitializer("admin", "password123", "1");

        when(credentialRepository.findByUsername("admin"))
                .thenReturn(Optional.of(existing));
        when(credentialRepository.findByUserId(1L))
                .thenReturn(Optional.of(existing));

        assertDoesNotThrow(() -> initializer.run(args));

        verify(credentialRepository, never()).save(any());
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void shouldCreateAdminWhenItDoesNotExist() {
        BootstrapAdminInitializer initializer =
                createInitializer("admin", "password123", "1");

        when(credentialRepository.findByUsername("admin"))
                .thenReturn(Optional.empty());
        when(credentialRepository.findByUserId(1L))
                .thenReturn(Optional.empty());
        when(passwordEncoder.encode("password123"))
                .thenReturn("encoded-password");

        initializer.run(args);

        ArgumentCaptor<Credential> captor =
                ArgumentCaptor.forClass(Credential.class);

        verify(credentialRepository).save(captor.capture());

        Credential saved = captor.getValue();

        assertEquals(1L, saved.getUserId());
        assertEquals("admin", saved.getUsername());
        assertEquals("encoded-password", saved.getPasswordHash());
        assertEquals(Role.ADMIN, saved.getRole());

        verify(passwordEncoder).encode("password123");
    }
}
