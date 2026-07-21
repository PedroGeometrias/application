package com.pedroharo.threatlens.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.http.HttpClient;
import java.time.Clock;

@Configuration
public class ApplicationConfiguration {
    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    HttpClient httpClient(ThreatLensProperties properties) {
        return HttpClient.newBuilder()
                .connectTimeout(properties.providers().timeout())
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }
}
