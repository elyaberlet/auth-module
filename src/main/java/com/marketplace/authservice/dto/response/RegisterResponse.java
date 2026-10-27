package com.marketplace.authservice.dto.response;

import com.marketplace.authservice.entity.Role;

public record RegisterResponse(
        Long userId,
        String username,
        Role role
) {
}
