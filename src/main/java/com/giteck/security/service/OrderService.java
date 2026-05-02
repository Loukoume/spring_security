package com.giteck.security.service;

import com.giteck.security.dto.CreateOrderRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class OrderService {

    @PreAuthorize("hasAuthority('ORDER_CREATE')")
    public String createOrder(CreateOrderRequest request, String username) {
        return "Commande creee par " + username + " : " + request.quantity() + " x " + request.product();
    }
}
