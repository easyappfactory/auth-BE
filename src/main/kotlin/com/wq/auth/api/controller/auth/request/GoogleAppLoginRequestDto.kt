package com.wq.auth.api.controller.auth.request

import io.swagger.v3.oas.annotations.media.Schema
import jakarta.validation.constraints.NotBlank

@Schema(description = "안드로이드 앱 전용 Google ID Token 로그인 요청 바디")
data class GoogleAppLoginRequestDto(
    @field:NotBlank(message = "idToken은 필수입니다")
    @field:Schema(
        description = "Google Credential Manager에서 발급받은 ID Token",
        example = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ij..."
    )
    val idToken: String,
)