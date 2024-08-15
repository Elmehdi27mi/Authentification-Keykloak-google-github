package net.mehdi.keycloakgoogle.web;

import lombok.AllArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

@Controller
@AllArgsConstructor
public class ControllerDemo {
    private ClientRegistrationRepository clientRegistrationRepository;

    @GetMapping("/pageDemo")
    @PreAuthorize("hasAuthority('ADMIN')")
    public String PageDemo() {
        return "page";
    }

    @GetMapping("/auth")
    @ResponseBody
    public Authentication authentication(Authentication authentication) {
        return authentication;
    }

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/notAuthorized")
    public String notAuthorized() {
        return "notAuthorized";
    }
    @GetMapping("/oauthLogin")
    public String oauthLogin(Model model) {
        String authorizationRequestBaseUri="oauth2/authorization";
        Map<String,String> oauth2AuthenticationUrls = new HashMap<>();
        Iterable<ClientRegistration>clientRegistrations=(Iterable<ClientRegistration>) clientRegistrationRepository;
        clientRegistrations.forEach(clientRegistration -> {
            oauth2AuthenticationUrls.put(clientRegistration.getClientName(),
                    authorizationRequestBaseUri+"/"+clientRegistration.getRegistrationId());
        });
        model.addAttribute("urls",oauth2AuthenticationUrls);

        return "oauthLogin";
    }
}
