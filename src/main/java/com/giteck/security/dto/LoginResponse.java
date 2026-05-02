package com.giteck.security.dto;

import java.util.List;

public record LoginResponse(
        String tokenType,
        String accessToken,
        String username,
        List<String> authorities
) {
}
