package com.wq.auth.api.domain.auth

import com.wq.auth.api.domain.auth.entity.AuthProviderEntity
import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.auth.entity.RefreshTokenEntity
import com.wq.auth.api.domain.auth.request.SocialLoginRequest
import com.wq.auth.api.domain.auth.response.SocialLoginResult
import com.wq.auth.api.domain.member.MemberRepository
import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.domain.oauth.OAuthUser
import com.wq.auth.api.domain.oauth.error.SocialLoginException
import com.wq.auth.api.domain.oauth.error.SocialLoginExceptionCode
import com.wq.auth.security.jwt.JwtProvider
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.LocalDateTime

/**
 * 소셜 로그인 서비스
 *
 * 소셜 로그인의 전체 플로우를 관리합니다:
 * 1. 소셜 제공자로부터 사용자 정보 조회
 * 2. 기존 회원 확인 또는 신규 회원 생성
 * 3. AuthProvider 엔티티 생성/업데이트
 * 4. JWT 토큰 발급
 */
@Service
@Transactional(readOnly = true)
class SocialLoginService(
    private val loginProviders: MutableList<LoginProvider>,
    private val authProviderRepository: AuthProviderRepository,
    private val memberRepository: MemberRepository,
    private val jwtProvider: JwtProvider,
    private val refreshTokenRepository: RefreshTokenRepository,
) {
    private val log = KotlinLogging.logger {}

    /**
     * 소셜 로그인을 처리합니다.
     *
     * @param request 소셜 로그인 요청 DTO
     * @return 소셜 로그인 응답 DTO (JWT 토큰 포함)
     */
    @Transactional
    fun processSocialLogin(request: SocialLoginRequest): SocialLoginResult {
        log.info { "소셜 로그인 처리 시작: ${request.providerType}" }
        val oauthUser = loginProviders.find { it.support(request.providerType) }
            ?.getUserInfo(request)
            ?: throw SocialLoginException(
                SocialLoginExceptionCode.UNSUPPORTED_PROVIDER
            )

        val (member, isNewMember) = findOrCreateMember(oauthUser, oauthUser.providerType)

        createOrUpdateAuthProvider(member, oauthUser, oauthUser.providerType)

        member.lastLoginAt = LocalDateTime.now()
        memberRepository.save(member)

        val accessToken = jwtProvider.createAccessToken(member.opaqueId, member.role)
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


    /**
     * 기존 회원을 찾거나 신규 회원을 생성합니다.
     *
     * @param oauthUser OAuth 사용자 정보
     * @param providerType 소셜 제공자 타입
     * @return Pair<회원 엔티티, 신규 회원 여부>
     */
    fun findOrCreateMember(
        oauthUser: OAuthUser,
        providerType: ProviderType
    ): Pair<MemberEntity, Boolean> {

        // AuthProvider 테이블에서 기존 회원 확인
        authProviderRepository.findByProviderIdAndProviderType(
            oauthUser.providerId,
            providerType
        )?.let{ existingAuthProvider ->
            log.info { "기존 회원 발견: ${existingAuthProvider.member.opaqueId}" }
            return Pair(existingAuthProvider.member, false)
        } ?: run{
            // 신규 회원 생성
            log.info { "신규 회원 생성: ${oauthUser.email}" }
            val newMember = MemberEntity.createSocialMember(
                nickname = oauthUser.getNickname(),
                isEmailVerified = oauthUser.verifiedEmail,
                primaryEmail = oauthUser.email
            )

            val savedMember = memberRepository.save(newMember)
            log.info { "신규 회원 생성 완료: ${savedMember.opaqueId}" }

            return Pair(savedMember, true)
        }

    }

    /**
     * AuthProvider 엔티티를 생성하거나 업데이트합니다.
     *
     * @param member 회원 엔티티
     * @param oauthUser OAuth 사용자 정보
     * @param providerType 소셜 제공자 타입
     */
    fun createOrUpdateAuthProvider(
        member: MemberEntity,
        oauthUser: OAuthUser,
        providerType: ProviderType
    ) {
        val existingAuthProvider = authProviderRepository.findByMemberAndProviderType(member, providerType)

        if (existingAuthProvider.isPresent) {
            // 기존 AuthProvider 업데이트
            val authProvider = existingAuthProvider.get()
            // providerId와 email을 업데이트하는 메서드 호출 (엔티티에 setter 메서드가 있어야 함)
            authProvider.updateProviderInfo(oauthUser.providerId, oauthUser.email)
            authProviderRepository.save(authProvider)
            log.info { "AuthProvider 업데이트 완료: ${member.opaqueId}" }
        } else {
            // 새로운 AuthProvider 생성
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