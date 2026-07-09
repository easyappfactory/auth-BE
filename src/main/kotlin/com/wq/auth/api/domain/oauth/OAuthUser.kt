package com.wq.auth.api.domain.oauth

import com.wq.auth.api.domain.auth.entity.ProviderType

/**
 * 도메인에서 사용하는 소셜 사용자 정보 값 타입
 * 
 * 외부 OAuth 제공자로부터 받은 사용자 정보를 도메인에서 사용할 수 있는 형태로 변환한 값 객체입니다.
 * 외부 API 응답 구조에 의존하지 않는 순수한 도메인 값 타입입니다.
 */
data class OAuthUser(
    val providerId: String,
    val email: String,
    val verifiedEmail: Boolean,
    val name: String?,
    val givenName: String? = null,
    val phoneNumber: String? = null,
    val providerType: ProviderType
) {
    /**
     * 닉네임을 생성합니다.
     * 우선순위: name -> givenName -> email의 @ 앞부분
     */
    fun getNickname(): String = when {
        !name.isNullOrBlank() -> name
        !givenName.isNullOrBlank() -> givenName
        else -> email.substringBefore("@")
    }

}
