package com.giteck.security.controller;

import com.giteck.security.dto.ApiMessage;
import com.giteck.security.dto.CreateOrderRequest;
import com.giteck.security.service.OrderService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
public class ApiDemoController {

    private final OrderService orderService;

    public ApiDemoController(OrderService orderService) {
        this.orderService = orderService;
    }

    @GetMapping("/api/public/hello")
    public ApiMessage apiPublic() {
        return ApiMessage.anonymous("Endpoint API public : aucune authentification requise.");
    }

    @GetMapping("/api/user/me")
    public Map<String, Object> currentUser(Authentication authentication) {
        return Map.of(
                "username", authentication.getName(),
                "authorities", authentication.getAuthorities(),
                "authenticated", authentication.isAuthenticated(),
                "timestamp", Instant.now().toString()
        );
    }

    @GetMapping("/api/admin/panel")
    public ApiMessage adminPanel(Authentication authentication) {
        return ApiMessage.authenticated("Endpoint ADMIN : exige hasRole('ADMIN').", authentication.getName());
    }

    @GetMapping("/api/reports/summary")
    public ApiMessage reportSummary(Authentication authentication) {
        return ApiMessage.authenticated("Endpoint REPORT : exige hasAuthority('REPORT_READ').", authentication.getName());
    }

    @PostMapping("/api/orders")
    public ResponseEntity<Map<String, String>> createApiOrder(@Valid @RequestBody CreateOrderRequest request,
                                                              Authentication authentication) {
        String message = orderService.createOrder(request, authentication.getName());
        return ResponseEntity.ok(Map.of("message", message));
    }

    @PostMapping("/api/webhooks/payment")
    public ResponseEntity<Map<String, String>> paymentWebhook(@RequestBody(required = false) Map<String, Object> payload) {
        return ResponseEntity.ok(Map.of(
                "message", "Webhook public pour pratiquer une exclusion CSRF ciblee.",
                "payloadPresent", String.valueOf(payload != null)
        ));
    }
}
