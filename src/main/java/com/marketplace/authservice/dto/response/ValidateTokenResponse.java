
package com.marketplace.authservice.dto.response;

public record ValidateTokenResponse(
        boolean valid,
        Long userId,
        String role
) {}
