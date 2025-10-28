package com.wq.auth.api.domain.auth

import com.wq.auth.api.domain.auth.request.SocialLinkRequest
import com.wq.auth.api.domain.member.MemberRepository
import com.wq.auth.api.domain.member.error.MemberException
import com.wq.auth.api.domain.member.error.MemberExceptionCode
import com.wq.auth.api.domain.oauth.error.SocialLoginException
import com.wq.auth.api.domain.oauth.error.SocialLoginExceptionCode
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

/**
 * 소셜 계정 연동 서비스
 *
 * 로그인된 상태에서 다른 소셜 제공자 계정을 연동하는 기능을 제공합니다.
 *
 * 연동 프로세스:
 * 1. 현재 로그인된 회원 정보 조회 (opaqueId 기반)
 * 2. 소셜 제공자로부터 사용자 정보 조회
 * 3-1. 연동 계정이 없는 경우: AuthProvider만 추가
 * 3-2. 연동 계정이 있는 경우: 두 계정 병합 처리
 */
@Service
@Transactional(readOnly = true)
class SocialLinkService(
    private val linkProviders: MutableList<LinkProvider>,
    private val memberConnector: MemberConnector,
    private val memberRepository: MemberRepository,
    private val authProviderRepository: AuthProviderRepository,
) {
    private val log = KotlinLogging.logger {}

    /**
     * 소셜 계정 연동을 처리합니다.
     *
     * @param currentOpaqueId 현재 로그인된 회원의 opaqueId
     * @param request 소셜 연동 요청
     */
    @Transactional
    fun processSocialLink(currentOpaqueId: String, request: SocialLinkRequest) {
        log.info { "소셜 계정 연동 시작: $currentOpaqueId -> ${request.providerType}" }

        // 현재 로그인된 회원 조회
        val currentMember = memberRepository.findByOpaqueId(currentOpaqueId)
            .orElseThrow { MemberException(MemberExceptionCode.MEMBER_NOT_FOUND) }

        // Provider별 연동 처리
        val oauthUser = linkProviders.find { it.support(request.providerType) }
            ?.processLink(currentMember, request)
            ?: throw SocialLoginException(SocialLoginExceptionCode.UNSUPPORTED_PROVIDER)

        memberConnector.linkAccountInternal(
            currentMember = currentMember,
            providerType = request.providerType,
            providerId = oauthUser.providerId,
            email = oauthUser.email,
            findExistingProvider = {
                authProviderRepository.findByProviderIdAndProviderType(
                    oauthUser.providerId,
                    request.providerType
                )
            }
        )

        log.info { "소셜 계정 연동 완료: $currentOpaqueId -> ${request.providerType}" }
    }
}


