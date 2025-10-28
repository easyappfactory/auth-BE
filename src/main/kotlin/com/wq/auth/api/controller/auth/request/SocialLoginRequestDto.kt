package com.wq.auth.api.controller.auth.request

import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.auth.request.SocialLoginRequest
import io.swagger.v3.oas.annotations.media.Schema
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull

/**
 * 범용 소셜 로그인 요청 DTO
 *
 * 프론트엔드에서 소셜 로그인 인가 코드를 백엔드로 전송할 때 사용합니다.
 * 각 소셜 제공자별 특성을 지원합니다:
 * - Google/Kakao: PKCE 방식 (codeVerifier 사용)
 * - Naver: 전통적인 OAuth2 방식 (state 사용)
 *
 * @param authCode 소셜 제공자로부터 받은 인가 코드 (필수)
 * @param codeVerifier PKCE 검증을 위한 코드 검증자 (Google, Kakao용 - 선택사항)
 * @param state CSRF 방지용 상태 값 (Naver용 - 선택사항)
 * @param providerType 소셜 로그인 제공자 타입 (GOOGLE, KAKAO, NAVER 등)
 * */
@Schema(description = "범용 소셜 로그인 요청")
data class SocialLoginRequestDto(

    @field:NotBlank(message = "인가 코드는 필수입니다")
    @field:Schema(description = "소셜 제공자로부터 받은 인가 코드", example = "4/0AX4XfWh...AbCdEfGhIj")
    val authCode: String,

    @field:Schema(
        description = "PKCE 검증용 코드 검증자 (Google, Kakao용 - 선택사항)",
        example = "NgAfIySigI...IVxKxbmrpg"
    )
    val codeVerifier: String,

    @field:Schema(
        description = "CSRF 방지용 상태 값 (Naver용 - 선택사항)",
        example = "random_state_string_12345"
    )
    val state: String?,

    @field:NotNull(message = "제공자 타입은 필수입니다")
    @field:Schema(description = "소셜 로그인 제공자 타입", example = "GOOGLE", allowableValues = ["GOOGLE", "KAKAO", "NAVER"])
    val providerType: ProviderType,

)

fun SocialLoginRequestDto.toDomain(): SocialLoginRequest =
    SocialLoginRequest(authCode = authCode, codeVerifier = codeVerifier, state = state, providerType = providerType)

