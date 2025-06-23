package com.moodify.gateway.filter;

import com.moodify.gateway.config.PublicEndpointConfig;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseToken;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.Tracer;
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

import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

@Component
public class TokenVerificationFilter implements GlobalFilter, Ordered {
    private final Logger logger = Logger.getLogger(TokenVerificationFilter.class.getName());
    private final PublicEndpointConfig publicEndpointConfig;
    private final String allowedOrigin;
    private final Tracer tracer;

    public TokenVerificationFilter(
        @Value("${cors.allowed-origin}") String allowedOrigin,
        PublicEndpointConfig publicEndpointConfig,
        OpenTelemetry openTelemetry
    ) {
        this.allowedOrigin = allowedOrigin;
        this.publicEndpointConfig = publicEndpointConfig;
        this.tracer = openTelemetry.getTracer("gateway:token-verification-filter");
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        long startTime = System.currentTimeMillis();
        String originHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.ORIGIN);

        Span span = tracer.spanBuilder("TokenVerificationFilter").startSpan();
        try (var scope = span.makeCurrent()) {
            if (originHeader != null && !originHeader.equals(this.allowedOrigin)) {
                return writeErrorResponse(exchange, HttpStatus.FORBIDDEN, "Invalid Origin header.")
                    .doOnSuccess(v -> {
                        long duration = System.currentTimeMillis() - startTime;
                        span.setAttribute("request.duration", duration);
                        span.setAttribute("http.status_code", exchange.getResponse().getStatusCode().value());
                        span.end();
                    });
            }

            String path = exchange.getRequest().getURI().getPath();
            HttpMethod method = exchange.getRequest().getMethod();
            span.setAttribute("http.path", path);
            span.setAttribute("http.method", method != null ? method.name() : "UNKNOWN");

            if (isPublicEndpoint(path, method)) {
                return chain.filter(exchange)
                    .doOnSuccess(v -> {
                        long duration = System.currentTimeMillis() - startTime;
                        span.setAttribute("request.duration", duration);
                        span.setAttribute("http.status_code", exchange.getResponse().getStatusCode().value());
                        span.end();
                    })
                    .doOnError(e -> {
                        span.setAttribute("error", true);
                        span.recordException(e);
                        span.end();
                    });
            }

            String authHeaders = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeaders == null || authHeaders.isBlank() || !authHeaders.startsWith("Bearer ")) {
                return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Missing or invalid Authorization header.")
                    .doOnSuccess(v -> {
                        long duration = System.currentTimeMillis() - startTime;
                        span.setAttribute("request.duration", duration);
                        span.setAttribute("http.status_code", exchange.getResponse().getStatusCode().value());
                        span.end();
                    });
            }

            String token = authHeaders.replace("Bearer ", "");
            try {
                FirebaseToken decodedToken = FirebaseAuth.getInstance().verifyIdToken(token);
                ServerWebExchange mutatedExchange = exchange.mutate()
                    .request(builder -> builder.header("X-User-Id", decodedToken.getUid()))
                    .build();
                return chain.filter(mutatedExchange)
                    .doOnSuccess(v -> {
                        long duration = System.currentTimeMillis() - startTime;
                        span.setAttribute("request.duration", duration);
                        span.setAttribute("http.status_code", exchange.getResponse().getStatusCode().value());
                        span.end();
                    })
                    .doOnError(e -> {
                        span.setAttribute("error", true);
                        span.recordException(e);
                        span.end();
                    });
            } catch (Exception e) {
                logger.warning("Token verification failed: " + e.getMessage());
                span.setAttribute("error", true);
                span.recordException(e);
                return writeErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Token verification failed: " + e.getMessage())
                    .doOnSuccess(v -> {
                        long duration = System.currentTimeMillis() - startTime;
                        span.setAttribute("request.duration", duration);
                        span.setAttribute("http.status_code", exchange.getResponse().getStatusCode().value());
                        span.end();
                    });
            }
        } catch (Exception e) {
            logger.severe("Error in TokenVerificationFilter: " + e.getMessage());
            span.setAttribute("error", true);
            span.recordException(e);
            return writeErrorResponse(exchange, HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error")
                .doOnSuccess(v -> {
                    long duration = System.currentTimeMillis() - startTime;
                    span.setAttribute("request.duration", duration);
                    span.setAttribute("http.status_code", exchange.getResponse().getStatusCode().value());
                    span.end();
                });
        }
    }

    private boolean isPublicEndpoint(String path, HttpMethod method) {
        return publicEndpointConfig.getPublicEndpoints().stream()
                .anyMatch(e -> path.equals(e.getPath()) && method != null && method.name().equalsIgnoreCase(e.getMethod()));
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