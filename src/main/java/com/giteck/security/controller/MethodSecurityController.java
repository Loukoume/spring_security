package com.giteck.security.controller;

import com.giteck.security.model.OwnedDocument;
import com.giteck.security.service.ReportService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class MethodSecurityController {

    private final ReportService reportService;

    public MethodSecurityController(ReportService reportService) {
        this.reportService = reportService;
    }

    @GetMapping("/api/method/report")
    public Map<String, String> methodReport() {
        return Map.of("message", reportService.readConfidentialReport());
    }

    @GetMapping("/api/method/admin-operation")
    public Map<String, String> adminOperation() {
        return Map.of("message", reportService.runAdminOperation());
    }

    @GetMapping("/api/method/documents/{owner}")
    public OwnedDocument documentByOwner(@PathVariable String owner) {
        return reportService.findOwnedDocument(owner);
    }
}
