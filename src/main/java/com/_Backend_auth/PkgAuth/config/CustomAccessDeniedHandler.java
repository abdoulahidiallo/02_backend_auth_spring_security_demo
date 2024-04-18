package com._Backend_auth.PkgAuth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com._Backend_auth.PkgAuth.handlers.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;

@Component
@Log4j2
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    /**
     * Gère la réponse HTTP lorsqu'un accès est refusé.
     *
     * @param request               La requête HTTP
     * @param response              La réponse HTTP
     * @param accessDeniedException L'exception d'accès refusé
     * @throws IOException En cas d'erreur lors de l'écriture de la réponse
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        log.error("Erreur d'accès refusé : {}", accessDeniedException.getMessage());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        // Créer un objet ErrorResponse avec les informations de l'erreur
        ErrorResponse body = ErrorResponse.builder()
                .status(HttpServletResponse.SC_FORBIDDEN)
                .error("Forbidden")
                .timestamp(Instant.now())
                .message(accessDeniedException.getMessage())
                .path(request.getServletPath())
                .build();

        // Configurer le ObjectMapper pour sérialiser les dates au format ISO 8601
        final ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);

        // Écrire l'objet ErrorResponse dans la réponse HTTP
        mapper.writeValue(response.getOutputStream(), body);
    }
}
