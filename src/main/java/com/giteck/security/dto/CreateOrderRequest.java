package com.giteck.security.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;

public record CreateOrderRequest(
        @NotBlank(message = "Le produit est obligatoire")
        String product,

        @Positive(message = "La quantité doit être positive")
        int quantity
) {
}
