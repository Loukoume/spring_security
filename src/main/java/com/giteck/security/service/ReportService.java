package com.giteck.security.service;

import com.giteck.security.model.OwnedDocument;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class ReportService {

    @PreAuthorize("hasAuthority('REPORT_READ')")
    public String readConfidentialReport() {
        return "Rapport confidentiel : trafic, chiffre d'affaires, indicateurs sensibles.";
    }

    @PreAuthorize("hasRole('ADMIN')")
    public String runAdminOperation() {
        return "Operation d'administration executee.";
    }

    @PostAuthorize("returnObject.owner == authentication.name")
    public OwnedDocument findOwnedDocument(String owner) {
        return new OwnedDocument(1L, owner, "Document personnel", "Contenu lisible uniquement par son proprietaire.");
    }
}
