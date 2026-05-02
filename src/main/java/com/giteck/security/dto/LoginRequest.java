package com.giteck.security.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank(message = "Le nom utilisateur est obligatoire")
        String username,

        @NotBlank(message = "Le mot de passe est obligatoire")
        String password
) {
}
