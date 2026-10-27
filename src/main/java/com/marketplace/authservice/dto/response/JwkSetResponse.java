package com.marketplace.authservice.dto.response;

import java.util.List;

public record JwkSetResponse(List<JwkKeyResponse> keys) {
}