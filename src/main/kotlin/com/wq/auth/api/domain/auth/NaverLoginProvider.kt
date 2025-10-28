package com.wq.auth.api.domain.auth

import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.auth.request.OAuthAuthCodeRequest
import com.wq.auth.api.domain.auth.request.SocialLoginRequest
import com.wq.auth.api.domain.oauth.OAuthUser
import com.wq.auth.api.external.oauth.NaverOAuthClient
import org.springframework.stereotype.Component

@Component
class NaverLoginProvider(
    private val naverOAuthClient: NaverOAuthClient,
) : LoginProvider {
    override fun support(providerType: ProviderType): Boolean {
        return providerType == ProviderType.NAVER
    }

    override fun getUserInfo(request: SocialLoginRequest): OAuthUser {
        return naverOAuthClient.getUserFromAuthCode(
            OAuthAuthCodeRequest(
                authCode = request.authCode,
                state = request.state!!,      // 네이버는 state 사용
                codeVerifier = request.codeVerifier
            )
        )
    }
}