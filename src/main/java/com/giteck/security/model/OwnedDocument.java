package com.giteck.security.model;

public record OwnedDocument(
        Long id,
        String owner,
        String title,
        String content
) {
}
