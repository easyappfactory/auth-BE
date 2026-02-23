package com.wq.auth.shared.config

import com.wq.auth.shared.rateLimiter.RateLimiterInterceptor
import org.springframework.context.annotation.Configuration
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import org.springframework.web.servlet.config.annotation.InterceptorRegistry

@Configuration
class WebConfig(
    private val rateLimiterInterceptor: RateLimiterInterceptor
) : WebMvcConfigurer {

    override fun addInterceptors(registry: InterceptorRegistry) {
        registry.addInterceptor(rateLimiterInterceptor)
            .addPathPatterns("/api/**")  // API 경로에만 적용
    }
}
