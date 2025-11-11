package com.wq.auth.api.domain.auth

import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.auth.request.OAuthAuthCodeRequest
import com.wq.auth.api.domain.auth.request.SocialLinkRequest
import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.domain.oauth.OAuthUser
import com.wq.auth.api.external.oauth.GoogleOAuthClient
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.stereotype.Component

/**
 * Google 계정 연동 Provider
 */
@Component
class GoogleLinkProvider(
    private val googleOAuthClient: GoogleOAuthClient,
) : LinkProvider {

    private val log = KotlinLogging.logger {}

    override fun processLink(currentMember: MemberEntity, linkRequest: SocialLinkRequest): OAuthUser {
        log.info { "Google 계정 연동 처리 시작: ${currentMember.opaqueId}" }

        // Google OAuth2로부터 사용자 정보 조회
        val authCodeRequest = OAuthAuthCodeRequest(
            authCode = linkRequest.authCode,
            codeVerifier = linkRequest.codeVerifier,
        )
        return googleOAuthClient.getUserFromAuthCode(authCodeRequest)

    }

    override fun support(providerType: ProviderType): Boolean {
        return providerType == ProviderType.GOOGLE
    }
}