package com.wq.auth.api.domain.auth

import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.auth.request.OAuthAuthCodeRequest
import com.wq.auth.api.domain.auth.request.SocialLinkRequest
import com.wq.auth.api.domain.oauth.OAuthUser
import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.external.oauth.NaverOAuthClient
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.stereotype.Component

/**
 * 네이버 계정 연동 Provider
 */
@Component
class NaverLinkProvider(
    private val naverOAuthClient: NaverOAuthClient,
) : LinkProvider {

    private val log = KotlinLogging.logger {}

    override fun processLink(currentMember: MemberEntity, linkRequest: SocialLinkRequest): OAuthUser {

        log.info { "Naver 계정 연동 처리 시작: ${currentMember.opaqueId}" }

        val authCodeRequest = OAuthAuthCodeRequest(
            authCode = linkRequest.authCode,
            codeVerifier = linkRequest.codeVerifier,
            state = linkRequest.state
        )

        return naverOAuthClient.getUserFromAuthCode(authCodeRequest)
    }

    override fun support(providerType: ProviderType): Boolean {
        return providerType == ProviderType.NAVER
    }
}