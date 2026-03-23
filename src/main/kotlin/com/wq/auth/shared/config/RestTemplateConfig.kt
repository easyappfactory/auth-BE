package com.wq.auth.shared.config

import org.springframework.boot.web.client.RestTemplateBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory
import org.springframework.web.client.RestTemplate
import java.time.Duration
import java.util.function.Supplier

@Configuration
class RestTemplateConfig {

    @Bean
    fun restTemplate(builder: RestTemplateBuilder): RestTemplate {
        return builder
            .requestFactory(Supplier { HttpComponentsClientHttpRequestFactory() })
            .connectTimeout(Duration.ofSeconds(3))
            .readTimeout(Duration.ofSeconds(3))
            .build()
    }
}
