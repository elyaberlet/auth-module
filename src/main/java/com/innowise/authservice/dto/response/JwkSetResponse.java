package com.innowise.authservice.dto.response;

import java.util.List;

public record JwkSetResponse(List<JwkKeyResponse> keys) {
}