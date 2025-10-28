package com.wq.auth.api.domain.auth

import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.auth.request.SocialLinkRequest
import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.domain.oauth.OAuthUser

/**
 * 소셜 계정 연동 Provider 인터페이스
 */
interface LinkProvider {
    fun processLink(currentMember: MemberEntity, linkRequest: SocialLinkRequest): OAuthUser
    fun support(providerType: ProviderType): Boolean
}
