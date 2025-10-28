package com.wq.auth.api.controller.auth.request

import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.auth.request.SocialLoginRequest
import io.swagger.v3.oas.annotations.media.Schema
import jakarta.validation.constraints.NotBlank

@Schema(description = "Naver 소셜 로그인 요청 바디")
data class NaverSocialLoginRequestDto(
    @field:NotBlank(message = "authCode는 필수입니다")
    @field:Schema(description = "Naver OAuth2에서 받은 인가 코드", example = "4/0AX4XfWh...AbCdEfGhIj")
    val authCode: String,

    @field:NotBlank(message = "state는 필수입니다")
    @field:Schema(description = "CSRF 방지용 상태 값", example = "random_state_string_12345")
    val state: String,

    @field:NotBlank(message = "codeVerifier는 필수입니다")
    @field:Schema(description = "PKCE 검증용 코드 검증자", example = "NgAfIySigI...IVxKxbmrpg")
    val codeVerifier: String,
)

fun NaverSocialLoginRequestDto.toDomain(): SocialLoginRequest =
    SocialLoginRequest(authCode, codeVerifier, state, ProviderType.NAVER)
