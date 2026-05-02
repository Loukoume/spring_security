package com.giteck.security.dto;

import java.time.Instant;

public record ApiMessage(
        String message,
        String username,
        Instant timestamp
) {
    public static ApiMessage anonymous(String message) {
        return new ApiMessage(message, "anonymous", Instant.now());
    }

    public static ApiMessage authenticated(String message, String username) {
        return new ApiMessage(message, username, Instant.now());
    }
}
