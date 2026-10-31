package com.marketplace.authservice.dto.request;

import jakarta.validation.constraints.NotBlank;

public record ValidateTokenRequest(
        @NotBlank(message = "Access token must not be blank")
        String accessToken
) {}
