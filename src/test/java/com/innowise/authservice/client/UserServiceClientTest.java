
package com.innowise.authservice.client;

import com.innowise.authservice.dto.request.UserServiceCreateUserRequest;
import com.innowise.authservice.dto.response.UserServiceUserResponse;
import com.innowise.authservice.service.JwtService;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.LocalDate;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class UserServiceClientTest {

    private static final String SERVICE_TOKEN = "test-service-token";

    private MockWebServer mockWebServer;
    private JwtService jwtService;
    private UserServiceClient userServiceClient;

    @BeforeEach
    void setUp() throws Exception {
        mockWebServer = new MockWebServer();
        mockWebServer.start();

        jwtService = mock(JwtService.class);
        when(jwtService.generateServiceAccessToken()).thenReturn(SERVICE_TOKEN);

        userServiceClient = new UserServiceClient(
                jwtService,
                WebClient.builder()
        );

        ReflectionTestUtils.setField(
                userServiceClient,
                "userServiceBaseUrl",
                mockWebServer.url("/").toString()
        );
    }

    @AfterEach
    void tearDown() throws Exception {
        mockWebServer.shutdown();
    }

    @Test
    void createUser_shouldSendPostRequestAndReturnUser() throws Exception {
        mockWebServer.enqueue(new MockResponse()
                .setResponseCode(201)
                .setHeader("Content-Type", "application/json")
                .setBody("""
                        {
                            "id": 42
                        }
                        """));

        UserServiceCreateUserRequest request =
                new UserServiceCreateUserRequest(
                        "John",
                        "Smith",
                        LocalDate.of(1995, 5, 15),
                        "john.smith@example.com"
                );

        UserServiceUserResponse response = userServiceClient.createUser(request);

        assertThat(response).isNotNull();
        assertThat(response.id()).isEqualTo(42L);

        RecordedRequest recordedRequest =
                mockWebServer.takeRequest(1, TimeUnit.SECONDS);

        assertThat(recordedRequest).isNotNull();
        assertThat(recordedRequest.getMethod()).isEqualTo("POST");
        assertThat(recordedRequest.getPath()).isEqualTo("/api/users");
        assertThat(recordedRequest.getHeader("Authorization"))
                .isEqualTo("Bearer " + SERVICE_TOKEN);
        assertThat(recordedRequest.getHeader("Content-Type"))
                .contains("application/json");

        String requestBody = recordedRequest.getBody().readUtf8();

        assertThat(requestBody)
                .contains("\"name\":\"John\"")
                .contains("\"surname\":\"Smith\"")
                .contains("\"birthDate\":[1995,5,15]")
                .contains("\"email\":\"john.smith@example.com\"");

        verify(jwtService).generateServiceAccessToken();
    }

    @Test
    void deleteUser_shouldSendDeleteRequest() throws Exception {
        mockWebServer.enqueue(new MockResponse()
                .setResponseCode(204));

        Long userId = 42L;

        userServiceClient.deleteUser(userId);

        RecordedRequest recordedRequest =
                mockWebServer.takeRequest(1, TimeUnit.SECONDS);

        assertThat(recordedRequest).isNotNull();
        assertThat(recordedRequest.getMethod()).isEqualTo("DELETE");
        assertThat(recordedRequest.getPath()).isEqualTo("/api/users/42");
        assertThat(recordedRequest.getHeader("Authorization"))
                .isEqualTo("Bearer " + SERVICE_TOKEN);

        verify(jwtService).generateServiceAccessToken();
    }
}
