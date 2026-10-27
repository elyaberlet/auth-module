package com.marketplace.authservice.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record JwkKeyResponse(
        String kty,
        String use,
        String alg,
        String kid,
        String n,
        String e
) {
}