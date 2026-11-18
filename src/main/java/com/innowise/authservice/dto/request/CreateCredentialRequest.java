package com.innowise.authservice.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;

public record CreateCredentialRequest(

        @NotBlank
        @Size(max = 100)
        String name,

        @NotBlank
        @Size(max = 100)
        String surname,

        @Past
        LocalDate birthDate,

        @NotBlank
        @Email
        @Size(max = 255)
        String email,

        @NotBlank
        @Size(max = 100)
        String username,

        @NotBlank
        @Size(min = 8, max = 72)
        String password
) {
}
