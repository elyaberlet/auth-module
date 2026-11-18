package com.innowise.authservice.config;

import com.innowise.authservice.entity.Credential;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.repository.CredentialRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Создаёт при старте служебную учётку с ролью SERVICE (для вызовов Order Service -> User Service).
 * Работает по образцу BootstrapAdminInitializer. Если переменные не заданы, ничего не делает.
 */
@Component
public class BootstrapServiceAccountInitializer implements ApplicationRunner {

    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final String username;
    private final String password;
    private final String userIdValue;

    public BootstrapServiceAccountInitializer(
            CredentialRepository credentialRepository,
            PasswordEncoder passwordEncoder,
            @Value("${SERVICE_ACCOUNT_USERNAME:}") String username,
            @Value("${SERVICE_ACCOUNT_PASSWORD:}") String password,
            @Value("${SERVICE_ACCOUNT_USER_ID:}") String userIdValue
    ) {
        this.credentialRepository = credentialRepository;
        this.passwordEncoder = passwordEncoder;
        this.username = username;
        this.password = password;
        this.userIdValue = userIdValue;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        boolean usernameMissing = username.isBlank();
        boolean passwordMissing = password.isBlank();
        boolean userIdMissing = userIdValue.isBlank();

        if (usernameMissing && passwordMissing && userIdMissing) {
            return;
        }
        if (usernameMissing || passwordMissing || userIdMissing) {
            throw new IllegalStateException(
                    "SERVICE_ACCOUNT_USERNAME, SERVICE_ACCOUNT_PASSWORD and "
                            + "SERVICE_ACCOUNT_USER_ID must all be configured");
        }
        if (password.length() < 8 || password.length() > 72) {
            throw new IllegalStateException("Service account password must contain 8 to 72 characters");
        }

        final long userId;
        try {
            userId = Long.parseLong(userIdValue);
        } catch (NumberFormatException exception) {
            throw new IllegalStateException("SERVICE_ACCOUNT_USER_ID must be a valid number", exception);
        }
        if (userId <= 0) {
            throw new IllegalStateException("SERVICE_ACCOUNT_USER_ID must be greater than zero");
        }

        var byUsername = credentialRepository.findByUsername(username);
        if (byUsername.isPresent()) {
            Credential credential = byUsername.get();
            if (credential.getRole() != Role.SERVICE || !credential.getUserId().equals(userId)) {
                throw new IllegalStateException("Service account username already belongs to a different account");
            }
            // Пароль в окружении поменяли: синхронизируем хеш
            if (!passwordEncoder.matches(password, credential.getPasswordHash())) {
                credential.setPasswordHash(passwordEncoder.encode(password));
                credentialRepository.save(credential);
            }
            return;
        }

        if (credentialRepository.findByUserId(userId).isPresent()) {
            throw new IllegalStateException("SERVICE_ACCOUNT_USER_ID already belongs to another account");
        }

        Credential credential = new Credential();
        credential.setUserId(userId);
        credential.setUsername(username);
        credential.setPasswordHash(passwordEncoder.encode(password));
        credential.setRole(Role.SERVICE);
        credentialRepository.save(credential);
    }
}
