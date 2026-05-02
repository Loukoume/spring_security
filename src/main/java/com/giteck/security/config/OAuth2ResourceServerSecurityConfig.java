package com.giteck.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@Profile("oauth2-demo")
public class OAuth2ResourceServerSecurityConfig {

    /**
     * Active ce profil uniquement si tu as un vrai issuer OAuth2/OIDC, par exemple Keycloak.
     * Exemple : mvn spring-boot:run -Dspring-boot.run.profiles=oauth2-demo
     * Il faut ensuite définir : spring.security.oauth2.resourceserver.jwt.issuer-uri=...
     */
    @Bean
    SecurityFilterChain oauth2ResourceServerChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(Customizer.withDefaults())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/api/public/**", "/actuator/health").permitAll()
                .requestMatchers("/api/reports/**").hasAuthority("SCOPE_report:read")
                .requestMatchers("/api/admin/**").hasAuthority("SCOPE_admin")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }
}
