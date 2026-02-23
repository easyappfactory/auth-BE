package com.wq.auth.api.domain.oauth.error

import com.wq.auth.shared.error.ApiResponseCode

/**
 * 소셜 로그인 관련 예외 코드
 * 
 * Google, 카카오, 네이버 등 소셜 로그인 처리 중 발생하는 예외들을 정의합니다.
 */
enum class SocialLoginExceptionCode(
    override val status: Int,
    override val message: String
) : ApiResponseCode {
    
    // Google OAuth 관련 예외
    GOOGLE_INVALID_AUTHORIZATION_CODE(400, "유효하지 않은 Google 인가 코드입니다"),
    GOOGLE_TOKEN_REQUEST_FAILED(400, "Google 액세스 토큰 요청이 실패했습니다"),
    GOOGLE_USER_INFO_REQUEST_FAILED(400, "Google 사용자 정보 조회가 실패했습니다"),
    GOOGLE_INVALID_ACCESS_TOKEN(401, "유효하지 않은 Google 액세스 토큰입니다"),
    GOOGLE_SERVER_ERROR(502, "Google 서버에서 일시적인 오류가 발생했습니다"),
    
    // 카카오 OAuth 관련 예외
    KAKAO_INVALID_AUTHORIZATION_CODE(400, "유효하지 않은 카카오 인가 코드입니다"),
    KAKAO_TOKEN_REQUEST_FAILED(400, "카카오 액세스 토큰 요청이 실패했습니다"),
    KAKAO_USER_INFO_REQUEST_FAILED(400, "카카오 사용자 정보 조회가 실패했습니다"),
    
    // 네이버 OAuth 관련 예외
    NAVER_INVALID_AUTHORIZATION_CODE(400, "유효하지 않은 네이버 인가 코드입니다"),
    NAVER_TOKEN_REQUEST_FAILED(400, "네이버 액세스 토큰 요청이 실패했습니다"),
    NAVER_USER_INFO_REQUEST_FAILED(400, "네이버 사용자 정보 조회가 실패했습니다"),
    NAVER_SERVER_ERROR(502, "Naver 서버에서 일시적인 오류가 발생했습니다"),
    NAVER_INVALID_ACCESS_TOKEN(401, "유효하지 않은 Naver 액세스 토큰입니다"),
    NAVER_INVALID_STATE(400, "유효하지 않은 네이버 state 값입니다"),

    // 공통 소셜 로그인 예외
    INVALID_REDIRECT_URI(400, "허용되지 않은 redirect_uri입니다. 등록된 redirect_uri만 사용할 수 있습니다."),
    UNSUPPORTED_PROVIDER(400, "지원하지 않는 소셜 로그인 제공자입니다"),
    SOCIAL_LOGIN_PROCESSING_ERROR(500, "소셜 로그인 처리 중 오류가 발생했습니다"),
    MEMBER_CREATION_FAILED(500, "소셜 로그인 회원 생성에 실패했습니다"),
    AUTH_PROVIDER_CREATION_FAILED(500, "인증 제공자 정보 생성에 실패했습니다"),

    // 소셜 계정 연동 관련 예외
    ALREADY_LINKED_ACCOUNT(409, "이미 연동된 계정입니다"),
    SOCIAL_LINK_PROCESSING_ERROR(500, "소셜 계정 연동 처리 중 오류가 발생했습니다"),
}
