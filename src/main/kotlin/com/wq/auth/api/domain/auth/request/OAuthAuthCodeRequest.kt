package com.wq.auth.api.domain.auth.request

/**
 * OAuth 인가 코드 교환 요청
 *
 * @param redirectUri 토큰 요청 시 사용할 redirect_uri. 없으면 서버 기본값 사용. 있으면 허용 목록에 있을 때만 사용.
 */
data class OAuthAuthCodeRequest(
    val authCode: String,
    val codeVerifier: String,
    val state: String? = null,  // 네이버만 사용
    val redirectUri: String? = null,
)
