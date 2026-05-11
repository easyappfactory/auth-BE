package com.wq.auth.api.controller.auth.response

import io.swagger.v3.oas.annotations.media.Schema

@Schema(description = "소셜 로그인 앱 응답 (X-Client-Id가 web이 아닌 경우 반환)")
data class SocialLoginResponseDto(
    @get:Schema(description = "JWT 액세스 토큰")
    val accessToken: String,

    @get:Schema(description = "JWT 리프레시 토큰")
    val refreshToken: String,
)
