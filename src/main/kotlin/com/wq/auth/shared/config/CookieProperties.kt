package com.wq.auth.shared.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "app.cookie")
data class CookieProperties(
    val domain: String,
    val secure: Boolean,
    val sameSite: String,
)
