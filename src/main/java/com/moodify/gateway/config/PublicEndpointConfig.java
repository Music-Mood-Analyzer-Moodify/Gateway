package com.moodify.gateway.config;

import com.moodify.gateway.models.Endpoint;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Data
@Component
@ConfigurationProperties(prefix = "auth")
public class PublicEndpointConfig {
    private List<Endpoint> publicEndpoints;
}