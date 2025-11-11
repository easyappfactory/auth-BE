package com.wq.auth.api.domain.auth

import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.auth.request.OAuthAuthCodeRequest
import com.wq.auth.api.domain.auth.request.SocialLoginRequest
import com.wq.auth.api.domain.oauth.OAuthUser
import com.wq.auth.api.external.oauth.GoogleOAuthClient
import org.springframework.stereotype.Component

@Component
class GoogleLoginProvider(
    private val googleOAuthClient: GoogleOAuthClient,
) : LoginProvider {
    override fun support(providerType: ProviderType): Boolean {
        return providerType == ProviderType.GOOGLE
    }

    override fun getUserInfo(request: SocialLoginRequest): OAuthUser {
        return googleOAuthClient.getUserFromAuthCode(
            OAuthAuthCodeRequest(
                request.authCode,
                request.codeVerifier
            )
        )
    }
}