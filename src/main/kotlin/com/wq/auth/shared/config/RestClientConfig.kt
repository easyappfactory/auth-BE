package com.wq.auth.shared.config

import org.apache.hc.client5.http.config.ConnectionConfig
import org.apache.hc.client5.http.config.RequestConfig
import org.apache.hc.client5.http.impl.classic.HttpClients
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder
import org.apache.hc.core5.util.Timeout
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory
import org.springframework.web.client.RestClient
import java.util.concurrent.TimeUnit

@Configuration
class RestClientConfig {

    @Bean
    fun restClient(): RestClient {
        // 1. Connection 설정 (Connect Timeout 설정)
        val connectionConfig = ConnectionConfig.custom()
            .setConnectTimeout(Timeout.of(3, TimeUnit.SECONDS))
            .build()

        // 2. Connection Manager 설정 (설정된 ConnectionConfig 적용)
        val connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
            .setDefaultConnectionConfig(connectionConfig)
            .build()

        // 3. Request 설정 (Response/Read Timeout 설정)
        val requestConfig = RequestConfig.custom()
            .setResponseTimeout(Timeout.of(3, TimeUnit.SECONDS))
            .build()

        // 4. HttpClient 생성 (Manager와 RequestConfig 결합)
        val httpClient = HttpClients.custom()
            .setConnectionManager(connectionManager)
            .setDefaultRequestConfig(requestConfig)
            .build()

        // 5. Factory 및 RestClient 빌드
        val factory = HttpComponentsClientHttpRequestFactory(httpClient)

        return RestClient.builder()
            .requestFactory(factory)
            .build()
    }
}