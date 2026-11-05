package com.innowise.authservice.dto.request;

import java.time.LocalDate;

public record UserServiceCreateUserRequest(
        String name,
        String surname,
        LocalDate birthDate,
        String email
) {
}