package com.marketplace.authservice.service;

import com.marketplace.authservice.dto.request.*;
import com.marketplace.authservice.dto.response.RegisterResponse;
import com.marketplace.authservice.dto.response.TokenResponse;
import com.marketplace.authservice.dto.response.ValidateTokenResponse;

public interface AuthService {

    RegisterResponse createCredential(CreateCredentialRequest request);

    TokenResponse login(LoginRequest request);

    TokenResponse refresh(RefreshTokenRequest request);

    ValidateTokenResponse validateToken(ValidateTokenRequest request);
}
