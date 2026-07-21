package com.pedroharo.threatlens;

import com.pedroharo.threatlens.config.ThreatLensProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(ThreatLensProperties.class)
public class ThreatLensApplication {
    public static void main(String[] args) {
        SpringApplication.run(ThreatLensApplication.class, args);
    }
}
