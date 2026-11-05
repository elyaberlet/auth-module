package com.innowise.authservice.service;

import com.innowise.authservice.dto.request.CreateCredentialRequest;
import com.innowise.authservice.dto.request.LoginRequest;
import com.innowise.authservice.dto.request.RefreshTokenRequest;
import com.innowise.authservice.dto.response.RegisterResponse;
import com.innowise.authservice.dto.response.TokenResponse;

public interface AuthService {

    RegisterResponse register(CreateCredentialRequest request);

    TokenResponse login(LoginRequest request);

    TokenResponse refresh(RefreshTokenRequest request);

}