package com.wq.auth.api.external.oauth

import org.springframework.stereotype.Component

/**
 * 토큰 교환 시 사용할 redirect_uri를 결정합니다.
 *
 * - 요청 바디에 redirectUri가 있으면 그 값을 사용
 * - null 또는 비어 있으면 서버 기본값(env의 *_REDIRECT_URI) 사용
 */
@Component
class OAuthRedirectUriResolver {
    fun resolve(requestRedirectUri: String?, defaultRedirectUri: String): String =
        if (requestRedirectUri.isNullOrBlank()) defaultRedirectUri else requestRedirectUri
}
