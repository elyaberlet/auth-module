package com.innowise.authservice.client;

import com.innowise.authservice.dto.request.UserServiceCreateUserRequest;
import com.innowise.authservice.dto.response.UserServiceUserResponse;
import com.innowise.authservice.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

@Component
@RequiredArgsConstructor
public class UserServiceClient {

    private final JwtService jwtService;
    private final WebClient.Builder webClientBuilder;

    @Value("${user-service.base-url}")
    private String userServiceBaseUrl;

    public UserServiceUserResponse createUser(UserServiceCreateUserRequest request) {
        String serviceToken = jwtService.generateServiceAccessToken();

        return webClientBuilder
                .baseUrl(userServiceBaseUrl)
                .build()
                .post()
                .uri("/api/users")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + serviceToken)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .retrieve()
                .bodyToMono(UserServiceUserResponse.class)
                .block();
    }

    public void deleteUser(Long userId) {
        String serviceToken = jwtService.generateServiceAccessToken();

        webClientBuilder
                .baseUrl(userServiceBaseUrl)
                .build()
                .delete()
                .uri("/api/users/{id}", userId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + serviceToken)
                .retrieve()
                .toBodilessEntity()
                .block();
    }
}