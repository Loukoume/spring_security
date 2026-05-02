package com.giteck.security.security;

import jakarta.annotation.PostConstruct;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class DemoUserDetailsService implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;
    private final Map<String, UserDetails> users = new HashMap<>();

    public DemoUserDetailsService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    void initUsers() {
        users.put("admin", User.withUsername("admin")
                .password(passwordEncoder.encode("password123"))
                .authorities("ROLE_ADMIN", "REPORT_READ", "ORDER_CREATE", "ORDER_WRITE")
                .build());

        users.put("user", User.withUsername("user")
                .password(passwordEncoder.encode("password123"))
                .authorities("ROLE_USER", "ORDER_CREATE")
                .build());

        users.put("reporter", User.withUsername("reporter")
                .password(passwordEncoder.encode("password123"))
                .authorities("ROLE_USER", "REPORT_READ")
                .build());
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails user = users.get(username);
        if (user == null) {
            throw new UsernameNotFoundException("Utilisateur introuvable : " + username);
        }
        return user;
    }
}
