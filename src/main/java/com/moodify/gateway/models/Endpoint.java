package com.moodify.gateway.models;

import lombok.Data;

@Data
public class Endpoint {
    private String path;
    private String method;
}