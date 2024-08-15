package net.mehdi.keycloakgoogle.sec;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;

import java.util.*;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    //differnt providers for registration
    private ClientRegistrationRepository clientRegistrationRepository;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(Customizer.withDefaults())
                .authorizeHttpRequests(auth->auth.requestMatchers("/","oauthLogin/**").permitAll())
                .authorizeHttpRequests(auth->auth.anyRequest().authenticated())
                .oauth2Login(oauth->oauth
                        .loginPage("/oauthLogin")
                        .defaultSuccessUrl("/"))
                .logout((logout)->logout
                        .logoutSuccessHandler(oidcLogoutSuccessHandler())
                        .logoutSuccessUrl("/").permitAll()
                        .deleteCookies("JSESSIONID"))
                .exceptionHandling(eh->eh.accessDeniedPage("/notAuthorized"))
                .build();
    }
    //for logout
    private OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler(){
        final OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler=
                new OidcClientInitiatedLogoutSuccessHandler(this.clientRegistrationRepository);
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}?logoutsuccess=true");
        return oidcLogoutSuccessHandler;
    }
    @Bean
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> {
            final Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
            authorities.forEach((authority) -> {
                if (authority instanceof OidcUserAuthority oidcAuth) {
                    mappedAuthorities.addAll(mapAuthorities(oidcAuth.getIdToken().getClaims()));
                    System.out.println(oidcAuth.getAttributes());
                } else if (authority instanceof OAuth2UserAuthority oauth2Auth) {
                    mappedAuthorities.addAll(mapAuthorities(oauth2Auth.getAttributes()));
                }
            });
            return mappedAuthorities;
        };
    }

    private List<SimpleGrantedAuthority> mapAuthorities(final Map<String, Object> attributes) {
        final Map<String, Object> realAccess = ((Map<String, Object>) attributes.getOrDefault("realm_access", Collections.emptyMap()));
        final Collection<String> roles = ((Collection<String>) realAccess.getOrDefault("roles", Collections.emptyList()));
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role))
                .toList();
    }


}
