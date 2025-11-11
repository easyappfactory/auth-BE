package com.wq.auth.api.domain.auth

import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.auth.request.SocialLoginRequest
import com.wq.auth.api.domain.oauth.OAuthUser

interface LoginProvider {
    fun support(providerType: ProviderType): Boolean
    fun getUserInfo(request: SocialLoginRequest): OAuthUser
}
