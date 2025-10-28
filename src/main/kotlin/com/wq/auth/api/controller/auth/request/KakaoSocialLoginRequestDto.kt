package com.wq.auth.api.controller.auth.request

import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.auth.request.SocialLoginRequest
import io.swagger.v3.oas.annotations.media.Schema
import jakarta.validation.constraints.NotBlank

@Schema(description = "카카오 소셜 로그인 요청 바디")
data class KakaoSocialLoginRequestDto(
    @field:NotBlank(message = "authCode는 필수입니다")
    @field:Schema(description = "카카오 OAuth2에서 받은 인가 코드", example = "9d8fYl7x2zQ...")
    val authCode: String,

    @field:NotBlank(message = "codeVerifier는 필수입니다")
    @field:Schema(description = "PKCE 검증용 코드 검증자 (카카오는 선택사항이지만 보안을 위해 권장)", example = "NgAfIySigI...IVxKxbmrpg")
    val codeVerifier: String
)

fun KakaoSocialLoginRequestDto.toDomain(): SocialLoginRequest =
    SocialLoginRequest(authCode, codeVerifier, null, ProviderType.KAKAO)
