package com.wq.auth.api.controller.auth.request

import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.auth.request.SocialLinkRequest
import io.swagger.v3.oas.annotations.media.Schema
import jakarta.validation.constraints.NotBlank

/**
 * 소셜 계정 연동 요청 DTO
 */
@Schema(description = "소셜 계정 연동 요청")
data class SocialLinkRequestDto(
    @field:NotBlank(message = "인가 코드는 필수입니다")
    @Schema(
        description = "소셜 제공자로부터 받은 인가 코드",
        example = "4/0AY0e-g7xK...",
        required = true
    )
    val authCode: String,

    @Schema(
        description = "PKCE 코드 검증자",
        example = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        required = false
    )
    val codeVerifier: String,

    @Schema(
        description = "State 파라미터 (네이버 로그인시 필수)",
        example = "RANDOM_STATE_STRING",
        required = false
    )
    val state: String? = null,

    @Schema(
        description = "소셜 제공자 타입",
        example = "GOOGLE",
        allowableValues = ["GOOGLE", "KAKAO", "NAVER"],
        required = true
    )
    val providerType: ProviderType,

    @Schema(description = "인가 요청 시 사용한 redirect_uri. 허용 목록에 있을 때만 사용. 없으면 서버 기본값 사용.")
    val redirectUri: String? = null,
) {
    fun toDomain() = SocialLinkRequest(
        authCode = authCode,
        codeVerifier = codeVerifier,
        state = state,
        providerType = providerType,
        redirectUri = redirectUri,
    )
}