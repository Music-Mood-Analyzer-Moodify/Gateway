package com.moodify.gateway.filter;

import com.moodify.gateway.config.PublicEndpointConfig;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseToken;

import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class TokenVerificationFilter implements GlobalFilter, Ordered {
    // Global filter makes the class run on all requests passing gateway. Ordered lets us control the execution order of the filters.

    private final Logger logger = Logger.getLogger(TokenVerificationFilter.class.getName());
    private PublicEndpointConfig publicEndpointConfig;
    private String allowedOrigin;

    public TokenVerificationFilter(@Value("${cors.allowed-origin}") String allowedOrigin, PublicEndpointConfig publicEndpointConfig) {
        this.allowedOrigin = allowedOrigin;
        this.publicEndpointConfig = publicEndpointConfig;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String originHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.ORIGIN);

        if (originHeader != null) {
            if (!originHeader.equals(this.allowedOrigin)) {
                return writeErrorResponse(exchange, HttpStatus.FORBIDDEN, "Invalid Origin header.");
            }
        }

        String path = exchange.getRequest().getURI().getPath();
        HttpMethod method = exchange.getRequest().getMethod();

        if (isPublicEndpoint(path, method)) {
            return chain.filter(exchange);
        }

        String authHeaders = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeaders == null || authHeaders.isBlank() || !authHeaders.startsWith("Bearer ")) {
            return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Missing or invalid Authorization header.");
        }
        
        String token = authHeaders.replace("Bearer ", "");

        try {
            FirebaseToken decodedToken = FirebaseAuth.getInstance().verifyIdToken(token);
            ServerWebExchange mutatedExchange = exchange.mutate()
                    .request(builder -> builder.header("X-User-Id", decodedToken.getUid()))
                    .build();
            return chain.filter(mutatedExchange);

        } catch (Exception e) {
            logger.warning("Token verification failed: " + e.getMessage());
            return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Token verification failed: " + e.getMessage());
        }
    }

    private boolean isPublicEndpoint(String path, HttpMethod method) {
        return publicEndpointConfig.getPublicEndpoints().stream()
                .anyMatch(e -> path.equals(e.getPath()) && method.name().equalsIgnoreCase(e.getMethod()));
    }

    @Override
    public int getOrder() {
        return -1;
    }

    private Mono<Void> writeErrorResponse(ServerWebExchange exchange, HttpStatus status, String message) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        DataBufferFactory bufferFactory = exchange.getResponse().bufferFactory();
        String body = "{\"error\": \"" + message + "\"}";
        DataBuffer buffer = bufferFactory.wrap(body.getBytes(StandardCharsets.UTF_8));
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}