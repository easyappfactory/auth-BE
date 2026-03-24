package com.wq.auth.api.external.oauth.dto

import com.fasterxml.jackson.annotation.JsonProperty

/**
 * Google OAuth2 사용자 정보 응답 DTO
 * 
 * Google UserInfo API의 응답을 파싱하기 위한 데이터 클래스입니다.
 */
data class GoogleUserInfoResponse(
    @field:JsonProperty("id")
    val id: String,

    @field:JsonProperty("email")
    val email: String,

    @field:JsonProperty("verified_email")
    val verifiedEmail: Boolean? = true,

    @field:JsonProperty("name")
    val name: String,

    @field:JsonProperty("given_name")
    val givenName: String? = null,

    @field:JsonProperty("family_name")
    val familyName: String? = null,

    @field:JsonProperty("picture")
    val picture: String? = null,

    @field:JsonProperty("locale")
    val locale: String? = null
) {
    /**
     * 닉네임을 생성합니다.
     * 우선순위: name -> givenName -> email의 @ 앞부분
     */
    fun getNickname(): String {
        return when {
            name.isNotBlank() -> name
            !givenName.isNullOrBlank() -> givenName
            else -> email.substringBefore("@")
        }
    }

    /**
     * Google 제공자 ID를 반환합니다.
     */
    fun getProviderId(): String = id
}
