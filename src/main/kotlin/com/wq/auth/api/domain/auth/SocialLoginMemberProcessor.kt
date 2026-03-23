package com.wq.auth.api.domain.auth

import com.wq.auth.api.domain.auth.entity.AuthProviderEntity
import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.auth.entity.RefreshTokenEntity
import com.wq.auth.api.domain.auth.response.SocialLoginResult
import com.wq.auth.api.domain.member.MemberRepository
import com.wq.auth.api.domain.member.MemberStatsService
import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.domain.oauth.OAuthUser
import com.wq.auth.security.jwt.JwtProvider
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class SocialLoginMemberProcessor(
    private val authProviderRepository: AuthProviderRepository,
    private val memberRepository: MemberRepository,
    private val jwtProvider: JwtProvider,
    private val refreshTokenRepository: RefreshTokenRepository,
    private val memberStatsService: MemberStatsService,
) {
    private val log = KotlinLogging.logger {}

    @Transactional
    fun processMemberAndIssueTokens(oauthUser: OAuthUser, providerType: ProviderType): SocialLoginResult {
        val (member, isNewMember) = findOrCreateMember(oauthUser, providerType)

        createOrUpdateAuthProvider(member, oauthUser, providerType)

        memberStatsService.updateLastLoginAtAsync(member.id)

        val accessToken = jwtProvider.createAccessToken(member.opaqueId)
        val refreshToken = jwtProvider.createRefreshToken(member.opaqueId)

        val jti = jwtProvider.getJti(refreshToken)
        val opaqueId = jwtProvider.getOpaqueId(refreshToken)
        val refreshTokenEntity = RefreshTokenEntity.of(member, jti, opaqueId)
        refreshTokenRepository.save(refreshTokenEntity)

        log.info { "소셜 로그인 완료: ${member.opaqueId}, 신규 회원: $isNewMember" }

        return SocialLoginResult(
            accessToken = accessToken,
            refreshToken = refreshToken
        )
    }

    private fun findOrCreateMember(
        oauthUser: OAuthUser,
        providerType: ProviderType
    ): Pair<MemberEntity, Boolean> {
        return authProviderRepository.findByProviderIdAndProviderType(
            oauthUser.providerId,
            providerType
        )?.let { existingAuthProvider ->
            log.info { "기존 회원 발견: ${existingAuthProvider.member.opaqueId}" }
            Pair(existingAuthProvider.member, false)
        } ?: run {
            log.info { "신규 회원 생성: ${oauthUser.email}" }
            val newMember = MemberEntity.createSocialMember(
                nickname = oauthUser.getNickname(),
                isEmailVerified = oauthUser.verifiedEmail,
                primaryEmail = oauthUser.email
            )
            val savedMember = memberRepository.save(newMember)
            log.info { "신규 회원 생성 완료: ${savedMember.opaqueId}" }
            Pair(savedMember, true)
        }
    }

    private fun createOrUpdateAuthProvider(
        member: MemberEntity,
        oauthUser: OAuthUser,
        providerType: ProviderType
    ) {
        authProviderRepository.findByMemberAndProviderType(member, providerType)?.let { authProvider ->
            authProvider.updateProviderInfo(oauthUser.providerId, oauthUser.email)
            authProviderRepository.save(authProvider)
            log.info { "AuthProvider 업데이트 완료: ${member.opaqueId}" }
        } ?: run {
            val authProvider = AuthProviderEntity(
                member = member,
                providerType = providerType,
                providerId = oauthUser.providerId,
                email = oauthUser.email
            )
            authProviderRepository.save(authProvider)
            log.info { "AuthProvider 생성 완료: ${member.opaqueId}" }
        }
    }
}
