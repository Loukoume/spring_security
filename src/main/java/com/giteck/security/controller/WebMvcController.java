package com.giteck.security.controller;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;

@Controller
public class WebMvcController {

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String index() {
        return """
                <html>
                    <head><title>G-ITECK Security Practice</title></head>
                    <body>
                        <h1>Projet pratique Spring Security</h1>
                        <ul>
                            <li><a href='/public/hello'>Page publique MVC</a></li>
                            <li><a href='/dashboard'>Dashboard protege</a></li>
                            <li><a href='/admin/dashboard'>Admin protege</a></li>
                            <li><a href='/login'>Login</a></li>
                        </ul>
                    </body>
                </html>
                """;
    }

    @GetMapping(value = "/public/hello", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String publicMvc() {
        return "<h1>Page MVC publique</h1><p>Aucune authentification requise.</p>";
    }

    @GetMapping(value = "/login", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String loginPage(CsrfToken csrfToken) {
        String csrfInput = csrfToken == null ? "" : "<input type='hidden' name='" + csrfToken.getParameterName() + "' value='" + csrfToken.getToken() + "'/>";
        return """
                <html>
                    <head><title>Connexion</title></head>
                    <body>
                        <h1>Connexion MVC</h1>
                        <p>Utilisateurs : admin/password123, user/password123, reporter/password123</p>
                        <form method='post' action='/login'>
                            <label>Username</label><input name='username' value='user'/><br/>
                            <label>Password</label><input name='password' type='password' value='password123'/><br/>
                            %s
                            <button type='submit'>Se connecter</button>
                        </form>
                    </body>
                </html>
                """.formatted(csrfInput);
    }

    @GetMapping(value = "/dashboard", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String dashboard(Authentication authentication) {
        return "<h1>Dashboard protege</h1><p>Connecte : " + authentication.getName() + "</p>";
    }

    @GetMapping(value = "/account/profile", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String profile(Authentication authentication) {
        return "<h1>Profil</h1><p>Utilisateur : " + authentication.getName() + "</p>";
    }

    @GetMapping(value = "/admin/dashboard", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String adminDashboard(Authentication authentication) {
        return "<h1>Administration</h1><p>Reserve au role ADMIN. Connecte : " + authentication.getName() + "</p>";
    }

    @PostMapping(value = "/orders/mvc", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String createMvcOrder(Authentication authentication) {
        return "<h1>Commande MVC creee</h1><p>CSRF valide. Utilisateur : " + authentication.getName() + "</p>";
    }

    @GetMapping("/csrf-token")
    @ResponseBody
    public Map<String, String> csrfToken(CsrfToken token) {
        return Map.of(
                "headerName", token.getHeaderName(),
                "parameterName", token.getParameterName(),
                "token", token.getToken()
        );
    }
}
