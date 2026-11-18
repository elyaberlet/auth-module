package com.innowise.authservice.config;

import com.innowise.authservice.entity.Credential;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.repository.CredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.ApplicationArguments;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BootstrapServiceAccountInitializerTest {

    private static final String USERNAME = "order-service";
    private static final String PASSWORD = "strongPassword1";
    private static final String USER_ID = "42";
    private static final long USER_ID_LONG = 42L;

    @Mock
    private CredentialRepository credentialRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private ApplicationArguments args;

    private BootstrapServiceAccountInitializer initializer(String username, String password, String userId) {
        return new BootstrapServiceAccountInitializer(
                credentialRepository, passwordEncoder, username, password, userId);
    }

    private Credential existingCredential(Role role, long userId, String hash) {
        Credential credential = new Credential();
        credential.setUserId(userId);
        credential.setUsername(USERNAME);
        credential.setPasswordHash(hash);
        credential.setRole(role);
        return credential;
    }

    @Test
    void run_whenAllVariablesBlank_doesNothing() {
        BootstrapServiceAccountInitializer init = initializer("", "", "");

        assertThatCode(() -> init.run(args)).doesNotThrowAnyException();

        verifyNoInteractions(credentialRepository, passwordEncoder);
    }

    @Test
    void run_whenAllVariablesWhitespace_doesNothing() {
        BootstrapServiceAccountInitializer init = initializer("   ", " ", "  ");

        assertThatCode(() -> init.run(args)).doesNotThrowAnyException();

        verifyNoInteractions(credentialRepository, passwordEncoder);
    }

    @ParameterizedTest
    @CsvSource({
            "order-service, '', ''",
            "'', strongPassword1, ''",
            "'', '', 42",
            "order-service, strongPassword1, ''",
            "order-service, '', 42",
            "'', strongPassword1, 42"
    })
    void run_whenConfiguredPartially_throwsIllegalState(String username, String password, String userId) {
        BootstrapServiceAccountInitializer init = initializer(username, password, userId);

        assertThatThrownBy(() -> init.run(args))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("must all be configured");

        verifyNoInteractions(credentialRepository);
    }

    @ParameterizedTest
    @ValueSource(strings = {"1234567", "short", "a"})
    void run_whenPasswordTooShort_throwsIllegalState(String password) {
        BootstrapServiceAccountInitializer init = initializer(USERNAME, password, USER_ID);

        assertThatThrownBy(() -> init.run(args))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("8 to 72");

        verifyNoInteractions(credentialRepository);
    }

    @Test
    void run_whenPasswordTooLong_throwsIllegalState() {
        BootstrapServiceAccountInitializer init = initializer(USERNAME, "a".repeat(73), USER_ID);

        assertThatThrownBy(() -> init.run(args))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("8 to 72");

        verifyNoInteractions(credentialRepository);
    }

    @ParameterizedTest
    @ValueSource(ints = {8, 72})
    void run_whenPasswordOnLengthBoundary_isAccepted(int length) {
        String password = "a".repeat(length);
        when(credentialRepository.findByUsername(USERNAME)).thenReturn(Optional.empty());
        when(credentialRepository.findByUserId(USER_ID_LONG)).thenReturn(Optional.empty());
        when(passwordEncoder.encode(password)).thenReturn("hash");

        initializer(USERNAME, password, USER_ID).run(args);

        verify(credentialRepository).save(any(Credential.class));
    }

    @ParameterizedTest
    @ValueSource(strings = {"abc", "12.5", "4 2", "9999999999999999999999"})
    void run_whenUserIdNotNumber_throwsIllegalStateWithCause(String userId) {
        BootstrapServiceAccountInitializer init = initializer(USERNAME, PASSWORD, userId);

        assertThatThrownBy(() -> init.run(args))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("valid number")
                .hasCauseInstanceOf(NumberFormatException.class);

        verifyNoInteractions(credentialRepository);
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "-1", "-100"})
    void run_whenUserIdNotPositive_throwsIllegalState(String userId) {
        BootstrapServiceAccountInitializer init = initializer(USERNAME, PASSWORD, userId);

        assertThatThrownBy(() -> init.run(args))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("greater than zero");

        verifyNoInteractions(credentialRepository);
    }

    @Test
    void run_whenAccountDoesNotExist_createsServiceCredential() {
        when(credentialRepository.findByUsername(USERNAME)).thenReturn(Optional.empty());
        when(credentialRepository.findByUserId(USER_ID_LONG)).thenReturn(Optional.empty());
        when(passwordEncoder.encode(PASSWORD)).thenReturn("encoded-hash");

        initializer(USERNAME, PASSWORD, USER_ID).run(args);

        ArgumentCaptor<Credential> captor = ArgumentCaptor.forClass(Credential.class);
        verify(credentialRepository).save(captor.capture());
        Credential saved = captor.getValue();
        assertThat(saved.getUsername()).isEqualTo(USERNAME);
        assertThat(saved.getUserId()).isEqualTo(USER_ID_LONG);
        assertThat(saved.getPasswordHash()).isEqualTo("encoded-hash");
        assertThat(saved.getRole()).isEqualTo(Role.SERVICE);
    }

    @Test
    void run_whenUserIdAlreadyUsedByAnotherAccount_throwsIllegalState() {
        when(credentialRepository.findByUsername(USERNAME)).thenReturn(Optional.empty());
        when(credentialRepository.findByUserId(USER_ID_LONG))
                .thenReturn(Optional.of(existingCredential(Role.USER, USER_ID_LONG, "hash")));

        assertThatThrownBy(() -> initializer(USERNAME, PASSWORD, USER_ID).run(args))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("already belongs to another account");

        verify(credentialRepository, never()).save(any());
    }

    @Test
    void run_whenSameAccountExistsAndPasswordMatches_doesNotSave() {
        Credential existing = existingCredential(Role.SERVICE, USER_ID_LONG, "old-hash");
        when(credentialRepository.findByUsername(USERNAME)).thenReturn(Optional.of(existing));
        when(passwordEncoder.matches(PASSWORD, "old-hash")).thenReturn(true);

        initializer(USERNAME, PASSWORD, USER_ID).run(args);

        verify(credentialRepository, never()).save(any());
        verify(passwordEncoder, never()).encode(any());
        assertThat(existing.getPasswordHash()).isEqualTo("old-hash");
    }

    @Test
    void run_whenSameAccountExistsAndPasswordChanged_updatesHash() {
        Credential existing = existingCredential(Role.SERVICE, USER_ID_LONG, "old-hash");
        when(credentialRepository.findByUsername(USERNAME)).thenReturn(Optional.of(existing));
        when(passwordEncoder.matches(PASSWORD, "old-hash")).thenReturn(false);
        when(passwordEncoder.encode(PASSWORD)).thenReturn("new-hash");

        initializer(USERNAME, PASSWORD, USER_ID).run(args);

        verify(credentialRepository).save(existing);
        assertThat(existing.getPasswordHash()).isEqualTo("new-hash");
        assertThat(existing.getRole()).isEqualTo(Role.SERVICE);
        assertThat(existing.getUserId()).isEqualTo(USER_ID_LONG);
    }

    @Test
    void run_whenUsernameBelongsToNonServiceRole_throwsIllegalState() {
        Credential existing = existingCredential(Role.USER, USER_ID_LONG, "hash");
        when(credentialRepository.findByUsername(USERNAME)).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> initializer(USERNAME, PASSWORD, USER_ID).run(args))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("already belongs to a different account");

        verify(credentialRepository, never()).save(any());
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void run_whenUsernameBelongsToServiceWithDifferentUserId_throwsIllegalState() {
        Credential existing = existingCredential(Role.SERVICE, 999L, "hash");
        when(credentialRepository.findByUsername(USERNAME)).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> initializer(USERNAME, PASSWORD, USER_ID).run(args))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("already belongs to a different account");

        verify(credentialRepository, never()).save(any());
        verifyNoInteractions(passwordEncoder);
    }
}
