package com.wq.auth.shared.config

import com.wq.auth.security.jwt.JwtProperties
import org.springframework.http.ResponseCookie
import org.springframework.stereotype.Component

@Component
class CookieFactory(
    private val jwtProperties: JwtProperties,
    private val cookieProperties: CookieProperties,
) {

    fun createAccessTokenCookie(accessToken: String): ResponseCookie {
        return baseCookieBuilder("accessToken", accessToken)
            .maxAge(jwtProperties.accessExp.toSeconds())
            .build()
    }

    fun createRefreshTokenCookie(refreshToken: String): ResponseCookie {
        return baseCookieBuilder("refreshToken", refreshToken)
            .maxAge(jwtProperties.refreshExp.toSeconds())
            .build()
    }

    fun expireAccessTokenCookie(): ResponseCookie {
        return baseCookieBuilder("accessToken", "")
            .maxAge(0)
            .build()
    }

    fun expireRefreshTokenCookie(): ResponseCookie {
        return baseCookieBuilder("refreshToken", "")
            .maxAge(0)
            .build()
    }

    private fun baseCookieBuilder(name: String, value: String): ResponseCookie.ResponseCookieBuilder {
        return ResponseCookie.from(name, value)
            .httpOnly(true)
            .secure(cookieProperties.secure)
            .domain(cookieProperties.domain)
            .path("/")
            .sameSite(cookieProperties.sameSite)
    }
}
