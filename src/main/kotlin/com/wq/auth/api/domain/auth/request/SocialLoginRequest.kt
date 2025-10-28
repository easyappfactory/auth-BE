package com.wq.auth.api.domain.auth.request

import com.wq.auth.api.domain.auth.entity.ProviderType

/**
 * 소셜 로그인 요청 도메인 모델
 *
 * 각 소셜 제공자별 OAuth2 방식을 지원합니다:
 * - Google/Kakao: PKCE 방식 (codeVerifier 사용)
 * - Naver: 전통적인 OAuth2 방식 (state 사용) + PKCE
 *
 * @param authCode 소셜 제공자로부터 받은 인가 코드
 * @param codeVerifier PKCE 검증용 코드 검증자
 * @param state CSRF 방지용 상태 값 (Naver용 - 선택사항)
 * @param providerType 소셜 로그인 제공자 타입
 */
data class SocialLoginRequest(
    val authCode: String,
    val codeVerifier: String,
    val state: String?,
    val providerType: ProviderType,
)