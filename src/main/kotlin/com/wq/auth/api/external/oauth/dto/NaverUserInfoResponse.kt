package com.wq.auth.api.external.oauth.dto

import com.fasterxml.jackson.annotation.JsonProperty

/**
 * Naver OAuth2 사용자 정보 응답 DTO
 *
 * Naver UserInfo API의 응답을 파싱하기 위한 데이터 클래스입니다.
 */
data class NaverUserInfoResponse(
    @field:JsonProperty("resultcode")
    val resultCode: String,

    @field:JsonProperty("message")
    val message: String,

    @field:JsonProperty("response")
    val response: NaverUserInfo
)

data class NaverUserInfo(
    @field:JsonProperty("id")
    val id: String,

    @field:JsonProperty("nickname")
    val nickname: String? = null,

    @field:JsonProperty("name")
    val name: String? = null,

    @field:JsonProperty("email")
    val email: String? = null,

    @field:JsonProperty("verified_email")
    val verifiedEmail: Boolean? = false,

    @field:JsonProperty("gender")
    val gender: String? = null,

    @field:JsonProperty("age")
    val age: String? = null,

    @field:JsonProperty("birthday")
    val birthday: String? = null,

    @field:JsonProperty("profile_image")
    val profileImage: String? = null,

    @field:JsonProperty("birthyear")
    val birthYear: String? = null,

    @field:JsonProperty("mobile")
    val mobile: String? = null
) {
    /**
     * 닉네임을 생성합니다.
     * 우선순위: nickname -> name -> email의 @ 앞부분 -> "사용자"
     */
    @JvmName("getGeneratedNickname")
    fun getNickname(): String {
        return when {
            !nickname.isNullOrBlank() -> nickname
            !name.isNullOrBlank() -> name
            !email.isNullOrBlank() -> email.substringBefore("@")
            else -> "사용자"
        }
    }

    /**
     * Naver 제공자 ID를 반환합니다.
     */
    fun getProviderId(): String = id
}