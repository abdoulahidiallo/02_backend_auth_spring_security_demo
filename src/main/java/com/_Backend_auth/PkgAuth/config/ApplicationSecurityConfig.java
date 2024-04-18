package com._Backend_auth.PkgAuth.config;

import com._Backend_auth.PkgAuth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationSecurityConfig {
    private final UserRepository userRepository;

    /**
     * Fournit une implémentation de l'interface fonctionnelle UserDetailsService, qui a une méthode loadByUsername
     * qui lève une exception UsernameNotFoundException si l'utilisateur n'est pas trouvé.
     *
     * @return une instance de UserDetailsService
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> (UserDetails) userRepository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException("Utilisateur non trouvé"));
    }

    /**
     * Fournit un fournisseur d'authentification (AuthenticationProvider) qui utilise l'implémentation
     * de UserDetailsService et un encodeur de mot de passe.
     *
     * @return une instance de AuthenticationProvider
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    /**
     * Fournit un gestionnaire d'authentification (AuthenticationManager) qui peut être utilisé
     * pour authentifier les utilisateurs.
     *
     * @param config la configuration d'authentification
     * @return une instance de AuthenticationManager
     * @throws Exception si une erreur se produit lors de la configuration de l'AuthenticationManager
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Fournit un encodeur de mot de passe qui utilise l'algorithme BCrypt.
     *
     * @return une instance de PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}