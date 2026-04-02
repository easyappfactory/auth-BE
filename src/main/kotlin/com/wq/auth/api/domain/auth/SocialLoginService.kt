package com.wq.auth.api.domain.auth

import com.wq.auth.api.domain.auth.request.SocialLoginRequest
import com.wq.auth.api.domain.auth.response.SocialLoginResult
import com.wq.auth.api.domain.oauth.error.SocialLoginException
import com.wq.auth.api.domain.oauth.error.SocialLoginExceptionCode
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.stereotype.Service

/**
 * 소셜 로그인 서비스
 *
 * 소셜 로그인의 전체 플로우를 관리합니다:
 * 1. 소셜 제공자로부터 사용자 정보 조회 (트랜잭션 밖에서 수행)
 * 2. 기존 회원 확인 또는 신규 회원 생성 및 토큰 발급 (트랜잭션 내에서 수행)
 */
@Service
class SocialLoginService(
    private val loginProviders: MutableList<LoginProvider>,
    private val socialLoginMemberProcessor: SocialLoginMemberProcessor,
) {
    private val log = KotlinLogging.logger {}

    /**
     * 소셜 로그인을 처리합니다.
     *
     * @param request 소셜 로그인 요청 DTO
     * @return 소셜 로그인 응답 DTO (JWT 토큰 포함)
     */
    fun processSocialLogin(request: SocialLoginRequest): SocialLoginResult {
        log.info { "소셜 로그인 처리 시작: ${request.providerType}" }

        // 1. 소셜 제공자로부터 사용자 정보 조회 (외부 네트워크 통신 - 트랜잭션 밖)
        val oauthUser = loginProviders.find { it.support(request.providerType) }
            ?.getUserInfo(request)
            ?: throw SocialLoginException(
                SocialLoginExceptionCode.UNSUPPORTED_PROVIDER
            )

        // 2. 회원 정보 처리 및 토큰 발급 (DB 트랜잭션 수행)
        return socialLoginMemberProcessor.processMemberAndIssueTokens(oauthUser, request.providerType)
    }
}
