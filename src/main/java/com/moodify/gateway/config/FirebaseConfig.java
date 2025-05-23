package com.moodify.gateway.config;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.io.IOException;

@Configuration
public class FirebaseConfig {    
    @Bean    
    public FirebaseApp initializeFirebase() throws IOException {        
        if (FirebaseApp.getApps().isEmpty()) {            
            FirebaseOptions options = FirebaseOptions.builder()
            .setCredentials(GoogleCredentials.getApplicationDefault())                    
            .build();
            return FirebaseApp.initializeApp(options);        
        }        
        return FirebaseApp.getInstance();
    }
}