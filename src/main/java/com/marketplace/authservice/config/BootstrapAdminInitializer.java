package com.marketplace.authservice.config;

import com.marketplace.authservice.entity.Credential;
import com.marketplace.authservice.entity.Role;
import com.marketplace.authservice.repository.CredentialRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class BootstrapAdminInitializer implements ApplicationRunner {

    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final String adminUsername;
    private final String adminPassword;
    private final String adminUserId;

    public BootstrapAdminInitializer(
            CredentialRepository credentialRepository,
            PasswordEncoder passwordEncoder,
            @Value("${app.bootstrap-admin.username:}") String adminUsername,
            @Value("${app.bootstrap-admin.password:}") String adminPassword,
            @Value("${app.bootstrap-admin.user-id:}") String adminUserId
    ) {
        this.credentialRepository = credentialRepository;
        this.passwordEncoder = passwordEncoder;
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;
        this.adminUserId = adminUserId;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        boolean usernameMissing = adminUsername.isBlank();
        boolean passwordMissing = adminPassword.isBlank();
        boolean userIdMissing = adminUserId.isBlank();

        if (usernameMissing && passwordMissing && userIdMissing) {
            return;
        }

        if (usernameMissing || passwordMissing || userIdMissing) {
            throw new IllegalStateException(
                    "ADMIN_USERNAME, ADMIN_PASSWORD and ADMIN_USER_ID "
                            + "must all be configured"
            );
        }

        if (adminPassword.length() < 8 || adminPassword.length() > 72) {
            throw new IllegalStateException(
                    "Bootstrap admin password must contain 8 to 72 characters"
            );
        }

        final Long userId;

        try {
            userId = Long.parseLong(adminUserId);
        } catch (NumberFormatException exception) {
            throw new IllegalStateException(
                    "ADMIN_USER_ID must be a valid number", exception
            );
        }

        if (userId <= 0) {
            throw new IllegalStateException(
                    "ADMIN_USER_ID must be greater than zero"
            );
        }

        credentialRepository.findByUsername(adminUsername)
                .ifPresent(credential -> {
                    if (credential.getRole() != Role.ADMIN
                            || !credential.getUserId().equals(userId)) {
                        throw new IllegalStateException(
                                "Bootstrap username already belongs to "
                                        + "a different account"
                        );
                    }
                });

        var existingCredential =
                credentialRepository.findByUserId(userId);

        if (existingCredential.isPresent()) {
            Credential credential = existingCredential.get();

            if (!credential.getUsername().equals(adminUsername)
                    || credential.getRole() != Role.ADMIN) {
                throw new IllegalStateException(
                        "ADMIN_USER_ID already belongs to another account"
                );
            }

            return;
        }

        Credential credential = new Credential();
        credential.setUserId(userId);
        credential.setUsername(adminUsername);
        credential.setPasswordHash(
                passwordEncoder.encode(adminPassword)
        );
        credential.setRole(Role.ADMIN);

        credentialRepository.save(credential);
    }
}
