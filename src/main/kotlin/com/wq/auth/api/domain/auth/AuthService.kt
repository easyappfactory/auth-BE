package com.wq.auth.api.domain.auth

import com.wq.auth.api.domain.email.AuthEmailService
import com.wq.auth.api.domain.auth.entity.AuthProviderEntity
import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.domain.auth.entity.RefreshTokenEntity
import com.wq.auth.api.domain.auth.error.AuthException
import com.wq.auth.api.domain.auth.error.AuthExceptionCode
import com.wq.auth.api.domain.auth.request.EmailLoginLinkRequest
import com.wq.auth.api.domain.member.MemberRepository
import com.wq.auth.api.domain.member.MemberStatsService
import com.wq.auth.api.domain.member.error.MemberException
import com.wq.auth.api.domain.member.error.MemberExceptionCode
import com.wq.auth.security.jwt.JwtProvider
import com.wq.auth.security.jwt.error.JwtException
import com.wq.auth.security.jwt.error.JwtExceptionCode
import com.wq.auth.shared.utils.NicknameGenerator
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant

@Service
class AuthService(
    private val authEmailService: AuthEmailService,
    private val memberRepository: MemberRepository,
    private val authProviderRepository: AuthProviderRepository,
    private val refreshTokenRepository: RefreshTokenRepository,
    private val jwtProvider: JwtProvider,
    private val nicknameGenerator: NicknameGenerator,
    private val memberConnector: MemberConnector,
    private val memberStatsService: MemberStatsService,
) {
    private val log = KotlinLogging.logger {}

    data class TokenResult(
        val accessToken: String,
        val refreshToken: String,
    )

    @Transactional
    fun emailLogin(email: String, deviceId: String?): TokenResult {
        val authProviderOfExistingUser = authProviderRepository.findByEmailAndProviderType(email, ProviderType.EMAIL)

        if (authProviderOfExistingUser != null) {
            val existingUser = authProviderOfExistingUser.member
            val opaqueId = existingUser.opaqueId
            val accessToken = jwtProvider.createAccessToken(
                opaqueId = existingUser.opaqueId,
                extraClaims = mapOf("deviceId" to deviceId)
            )

            val existingRefreshToken = refreshTokenRepository.findActiveByMemberAndDeviceId(existingUser, deviceId)
            if (existingRefreshToken != null) {
                refreshTokenRepository.softDeleteByMemberAndDeviceId(existingUser, deviceId, Instant.now())
            }

            val refreshToken = jwtProvider.createRefreshToken(opaqueId = existingUser.opaqueId)
            val jti = jwtProvider.getJti(refreshToken)

            val refreshTokenEntity = RefreshTokenEntity.of(existingUser, jti, opaqueId, deviceId)
            refreshTokenRepository.save(refreshTokenEntity)
            
            memberStatsService.updateLastLoginAtAsync(existingUser.id)

            return TokenResult(accessToken, refreshToken)
        }

        return signUp(email, deviceId)
    }

    @Transactional
    fun signUp(email: String, deviceId: String?): TokenResult {
        authEmailService.validateEmailFormat(email)

        var nickname: String
        do {
            nickname = nicknameGenerator.generate()
        } while (memberRepository.existsByNickname(nickname))
        
        val member = MemberEntity.createEmailVerifiedMember(nickname, email)
        val opaqueId = member.opaqueId

        try {
            memberRepository.save(member)
            val provider = AuthProviderEntity.createEmailProvider(member, email)
            authProviderRepository.save(provider)
        } catch (ex: Exception) {
            throw AuthException(AuthExceptionCode.DATABASE_SAVE_FAILED, ex)
        }

        val accessToken = jwtProvider.createAccessToken(
            opaqueId = member.opaqueId,
            extraClaims = mapOf("deviceId" to deviceId)
        )
        val refreshToken = jwtProvider.createRefreshToken(opaqueId = member.opaqueId)
        val jti = jwtProvider.getJti(refreshToken)

        val refreshTokenEntity = RefreshTokenEntity.of(member, jti, opaqueId, deviceId)
        refreshTokenRepository.save(refreshTokenEntity)

        return TokenResult(accessToken, refreshToken)
    }

    @Transactional
    fun processEmailLoginLink(currentOpaqueId: String, request: EmailLoginLinkRequest) {
        log.info { "이메일 연동 시작: $currentOpaqueId -> ${request.email}" }

        val currentMember = memberRepository.findByOpaqueId(currentOpaqueId)
            .orElseThrow { MemberException(MemberExceptionCode.MEMBER_NOT_FOUND) }

        authEmailService.verifyCode(request.email, request.verifyCode)

        memberConnector.linkAccountInternal(
            currentMember = currentMember,
            providerType = ProviderType.EMAIL,
            providerId = null,
            email = request.email,
            findExistingProvider = {
                authProviderRepository.findByEmailAndProviderType(
                    request.email,
                    ProviderType.EMAIL
                )
            }
        )

        log.info { "이메일 연동 완료: $currentOpaqueId -> ${request.email}" }
    }

    @Transactional
    fun logout(refreshToken: String?) {
        if (refreshToken.isNullOrBlank()) {
            log.info { "refreshToken이 없는 상태로 로그아웃 시도" }
            return
        }

        try {
            jwtProvider.validateOrThrow(refreshToken)
            val opaqueId = jwtProvider.getOpaqueId(refreshToken)
            val jti = jwtProvider.getJti(refreshToken)
            refreshTokenRepository.softDeleteByOpaqueIdAndJti(opaqueId, jti, Instant.now())
        } catch (e: JwtException) {
            log.info { "만료된 refreshToken으로 로그아웃: ${e.message}" }
        } catch (ex: Exception) {
            throw AuthException(AuthExceptionCode.LOGOUT_FAILED, ex)
        }
    }

    @Transactional
    fun refreshAccessToken(refreshToken: String, deviceId: String?): TokenResult {
        jwtProvider.validateOrThrow(refreshToken)

        val jti = jwtProvider.getJti(refreshToken)
        val opaqueId = jwtProvider.getOpaqueId(refreshToken)

        refreshTokenRepository.findActiveByOpaqueIdAndJti(opaqueId, jti)
            ?: throw JwtException(JwtExceptionCode.MALFORMED)

        if (jwtProvider.getRefreshTokenExpiredAt(refreshToken).isBefore(Instant.now())) {
            refreshTokenRepository.softDeleteByOpaqueIdAndJti(opaqueId, jti, Instant.now())
            throw JwtException(JwtExceptionCode.EXPIRED)
        }

        val newAccessToken = jwtProvider.createAccessToken(
            opaqueId = opaqueId,
            extraClaims = mapOf("deviceId" to deviceId)
        )
        val newRefreshToken = jwtProvider.createRefreshToken(opaqueId = opaqueId)
        val newJti = jwtProvider.getJti(newRefreshToken)

        refreshTokenRepository.softDeleteByOpaqueIdAndJti(opaqueId, jti, Instant.now())

        val member = memberRepository.findByOpaqueId(opaqueId).get()
        val newRefreshTokenEntity = RefreshTokenEntity.of(member, newJti, opaqueId, deviceId)
        refreshTokenRepository.save(newRefreshTokenEntity)

        return TokenResult(newAccessToken, newRefreshToken)
    }
}
