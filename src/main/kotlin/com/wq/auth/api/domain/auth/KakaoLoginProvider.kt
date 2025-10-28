package com.wq.auth.api.domain.auth

import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.auth.request.OAuthAuthCodeRequest
import com.wq.auth.api.domain.auth.request.SocialLoginRequest
import com.wq.auth.api.domain.oauth.OAuthUser
import com.wq.auth.api.external.oauth.KakaoOAuthClient
import org.springframework.stereotype.Component

@Component
class KakaoLoginProvider(
    private val kakaoOAuthClient: KakaoOAuthClient,
) : LoginProvider {
    override fun support(providerType: ProviderType): Boolean {
        return providerType == ProviderType.KAKAO
    }

    override fun getUserInfo(request: SocialLoginRequest): OAuthUser {
        return kakaoOAuthClient.getUserFromAuthCode(
            OAuthAuthCodeRequest(
                request.authCode,
                request.codeVerifier
            )
        )
    }

}
