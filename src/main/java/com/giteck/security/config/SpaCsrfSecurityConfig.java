package com.giteck.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@Profile("spa-csrf-demo")
public class SpaCsrfSecurityConfig {

    /**
     * Active ce profil pour pratiquer le cas SPA + cookie de session + token CSRF lisible par JavaScript :
     * mvn spring-boot:run -Dspring-boot.run.profiles=spa-csrf-demo
     */
    @Bean
    SecurityFilterChain spaCsrfSecurityChain(HttpSecurity http,
                                             AuthenticationProvider authenticationProvider) throws Exception {
        http
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            )
            .cors(Customizer.withDefaults())
            .authenticationProvider(authenticationProvider)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login", "/public/**", "/api/auth/login", "/api/public/**", "/actuator/health").permitAll()
                .requestMatchers("/api/admin/**", "/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/dashboard", true)
                .permitAll()
            );

        return http.build();
    }
}
