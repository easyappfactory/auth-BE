package com.wq.auth.api.domain.auth.request

import com.wq.auth.api.domain.auth.entity.ProviderType

/**
 * 소셜 계정 연동 요청 도메인 모델
 *
 * @param redirectUri 인가 요청 시 사용한 redirect_uri. 없으면 서버 기본값 사용.
 */
data class SocialLinkRequest(
    val authCode: String,
    val codeVerifier: String,
    val state: String? = null,
    val providerType: ProviderType,
    val redirectUri: String? = null,
)