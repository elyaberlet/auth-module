package com.innowise.authservice.dto.response;

import com.innowise.authservice.entity.Role;

public record RegisterResponse(
        Long userId,
        String username,
        Role role
) {
}
