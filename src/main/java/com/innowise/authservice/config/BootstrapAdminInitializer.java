
package com.innowise.authservice.config;

import com.innowise.authservice.client.UserServiceClient;
import com.innowise.authservice.dto.request.UserServiceCreateUserRequest;
import com.innowise.authservice.dto.response.UserServiceUserDetailsResponse;
import com.innowise.authservice.dto.response.UserServiceUserResponse;
import com.innowise.authservice.entity.Credential;
import com.innowise.authservice.entity.Role;
import com.innowise.authservice.repository.CredentialRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class BootstrapAdminInitializer implements ApplicationRunner {

    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserServiceClient userServiceClient;

    private final String adminUsername;
    private final String adminPassword;
    private final String adminName;
    private final String adminSurname;
    private final String adminEmail;

    public BootstrapAdminInitializer(
            CredentialRepository credentialRepository,
            PasswordEncoder passwordEncoder,
            UserServiceClient userServiceClient,
            @Value("${app.bootstrap-admin.username:}") String adminUsername,
            @Value("${app.bootstrap-admin.password:}") String adminPassword,
            @Value("${app.bootstrap-admin.name:}") String adminName,
            @Value("${app.bootstrap-admin.surname:}") String adminSurname,
            @Value("${app.bootstrap-admin.email:}") String adminEmail
    ) {
        this.credentialRepository = credentialRepository;
        this.passwordEncoder = passwordEncoder;
        this.userServiceClient = userServiceClient;
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;
        this.adminName = adminName;
        this.adminSurname = adminSurname;
        this.adminEmail = adminEmail;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (allConfigurationMissing()) {
            return;
        }

        validateConfiguration();

        var existingCredential =
                credentialRepository.findByUsername(adminUsername);

        if (existingCredential.isPresent()) {
            verifyExistingAdmin(existingCredential.get());
            return;
        }

        UserServiceUserDetailsResponse existingUser =
                userServiceClient.findUserByEmail(adminEmail);

        boolean profileCreated = false;
        Long userId;

        if (existingUser != null) {
            userId = existingUser.id();
        } else {
            UserServiceUserResponse createdUser =
                    userServiceClient.createUser(
                            new UserServiceCreateUserRequest(
                                    adminName,
                                    adminSurname,
                                    null,
                                    adminEmail
                            )
                    );

            if (createdUser == null || createdUser.id() == null) {
                throw new IllegalStateException(
                        "User Service returned an invalid admin user ID"
                );
            }

            userId = createdUser.id();
            profileCreated = true;
        }

        if (userId <= 0) {
            throw new IllegalStateException(
                    "Admin user ID must be greater than zero"
            );
        }

        if (credentialRepository.findByUserId(userId).isPresent()) {
            throw new IllegalStateException(
                    "Admin profile ID already belongs to another credential"
            );
        }

        try {
            Credential credential = new Credential();
            credential.setUserId(userId);
            credential.setUsername(adminUsername);
            credential.setPasswordHash(
                    passwordEncoder.encode(adminPassword)
            );
            credential.setRole(Role.ADMIN);

            credentialRepository.saveAndFlush(credential);
        } catch (RuntimeException exception) {
            if (profileCreated) {
                try {
                    userServiceClient.deleteUser(userId);
                } catch (RuntimeException compensationException) {
                    exception.addSuppressed(compensationException);
                }
            }

            throw exception;
        }
    }

    private boolean allConfigurationMissing() {
        return adminUsername.isBlank()
                && adminPassword.isBlank()
                && adminName.isBlank()
                && adminSurname.isBlank()
                && adminEmail.isBlank();
    }

    private void validateConfiguration() {
        if (adminUsername.isBlank()
                || adminPassword.isBlank()
                || adminName.isBlank()
                || adminSurname.isBlank()
                || adminEmail.isBlank()) {
            throw new IllegalStateException(
                    "ADMIN_USERNAME, ADMIN_PASSWORD, ADMIN_NAME, "
                            + "ADMIN_SURNAME and ADMIN_EMAIL "
                            + "must all be configured"
            );
        }

        if (adminPassword.length() < 8 || adminPassword.length() > 72) {
            throw new IllegalStateException(
                    "Bootstrap admin password must contain 8 to 72 characters"
            );
        }
    }

    private void verifyExistingAdmin(Credential credential) {
        if (credential.getRole() != Role.ADMIN) {
            throw new IllegalStateException(
                    "Bootstrap username already belongs to a non-admin account"
            );
        }

        UserServiceUserDetailsResponse profile =
                userServiceClient.findUserByEmail(adminEmail);

        if (profile == null || !profile.id().equals(credential.getUserId())) {
            throw new IllegalStateException(
                    "Existing admin credentials do not match the User Service profile"
            );
        }
    }
}
