package com.wq.auth.api.domain.auth

import com.wq.auth.api.domain.email.AuthEmailService
import com.wq.auth.api.domain.auth.entity.AuthProviderEntity
import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.domain.auth.entity.RefreshTokenEntity
import com.wq.auth.api.domain.member.entity.Role
import com.wq.auth.api.domain.auth.error.AuthException
import com.wq.auth.api.domain.auth.error.AuthExceptionCode
import com.wq.auth.api.domain.auth.request.EmailLoginLinkRequest
import com.wq.auth.api.domain.member.MemberRepository
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
import java.time.LocalDateTime

@Service
class AuthService(
    private val authEmailService: AuthEmailService,
    private val memberRepository: MemberRepository,
    private val authProviderRepository: AuthProviderRepository,
    private val refreshTokenRepository: RefreshTokenRepository,
    private val jwtProvider: JwtProvider,
    private val nicknameGenerator: NicknameGenerator,
    private val memberConnector: MemberConnector,

    ) {
    private val log = KotlinLogging.logger {}

    data class TokenResult(
        val accessToken: String,
        val refreshToken: String,
    )

    @Transactional
    fun emailLogin(email: String, deviceId: String?): TokenResult {

        authProviderRepository.findByEmailAndProviderType(email, ProviderType.EMAIL)
            ?.let { authProviderOfExistingUser ->
                val existingUser = authProviderOfExistingUser.member
                // 이미 가입된 사용자 → 로그인 처리 및 JWT 발급
                val opaqueId = existingUser.opaqueId
                val accessToken =
                    jwtProvider.createAccessToken(
                        opaqueId = existingUser.opaqueId,
                        role = Role.MEMBER,
                        extraClaims = mapOf("deviceId" to deviceId)
                    )

                val existingRefreshToken = refreshTokenRepository.findActiveByMemberAndDeviceId(existingUser, deviceId)

                //이전 리프레시토큰 soft delete 처리
                if (existingRefreshToken != null) {
                    refreshTokenRepository.softDeleteByMemberAndDeviceId(existingUser, deviceId, Instant.now())
                }

                val refreshToken = jwtProvider.createRefreshToken(opaqueId = existingUser.opaqueId)
                val jti = jwtProvider.getJti(refreshToken)

                val refreshTokenEntity = RefreshTokenEntity.of(existingUser, jti, opaqueId, deviceId)
                refreshTokenRepository.save(refreshTokenEntity)
                existingUser.lastLoginAt = LocalDateTime.now()

                return TokenResult(accessToken, refreshToken)
            } ?: run {
            // 신규 사용자면 회원가입 진행
            return signUp(email, deviceId)
        }

    }

    @Transactional
    fun signUp(email: String, deviceId: String?): TokenResult {

        authEmailService.validateEmailFormat(email)

        var nickname: String
        do {
            nickname = nicknameGenerator.generate()
            //중복 닉네임인 경우
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
            role = Role.MEMBER,
            extraClaims = mapOf("deviceId" to deviceId)
        )
        val refreshToken = jwtProvider.createRefreshToken(opaqueId = member.opaqueId)
        val jti = jwtProvider.getJti(refreshToken)

        val refreshTokenEntity = RefreshTokenEntity.of(member, jti, opaqueId, deviceId)
        refreshTokenRepository.save(refreshTokenEntity)

        return TokenResult(accessToken, refreshToken)
    }

    /**
     * 이메일 계정 연동
     *
     * @param currentOpaqueId 현재 로그인된 회원의 opaqueId
     * @param request 이메일 인증 확인 요청
     */
    @Transactional
    fun processEmailLoginLink(currentOpaqueId: String, request: EmailLoginLinkRequest) {
        log.info { "이메일 연동 시작: $currentOpaqueId -> ${request.email}" }

        // 현재 로그인된 회원 조회
        val currentMember = memberRepository.findByOpaqueId(currentOpaqueId)
            .orElseThrow { MemberException(MemberExceptionCode.MEMBER_NOT_FOUND) }

        // 1. 인증 코드 확인
        authEmailService.verifyCode(request.email, request.verifyCode)

        // 2. 이메일이 다른 계정에 연동되어 있는지 확인
        // 있다면, 해당 계정에 연동되어있던 계정 연동
        // 없다면, 해당 계정에 이메일 provider 추가
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
            // 토큰 유효성 검사
            jwtProvider.validateOrThrow(refreshToken)

            // 유효한 토큰인 경우 soft delete 처리
            val opaqueId = jwtProvider.getOpaqueId(refreshToken)
            val jti = jwtProvider.getJti(refreshToken)
            refreshTokenRepository.softDeleteByOpaqueIdAndJti(opaqueId, jti, Instant.now())

        } catch (e: JwtException) {
            // 만료된 토큰이어도 로그아웃 성공으로 처리
            log.info { "만료된 refreshToken으로 로그아웃: ${e.message}" }
        } catch (ex: Exception) {
            // DB 삭제 실패 시에만 예외 발생
            throw AuthException(AuthExceptionCode.LOGOUT_FAILED, ex)
        }
    }

    @Transactional
    fun refreshAccessToken(refreshToken: String, deviceId: String?): TokenResult {
        //토큰 유효성 검사
        jwtProvider.validateOrThrow(refreshToken)

        val jti = jwtProvider.getJti(refreshToken)
        val opaqueId = jwtProvider.getOpaqueId(refreshToken)

        //토큰 jti+opaqueId로 DB에 있는지 확인
        refreshTokenRepository.findActiveByOpaqueIdAndJti(opaqueId, jti)
            ?: throw JwtException(JwtExceptionCode.MALFORMED)

        //토큰 엔티티 만료 기간 확인
        if (jwtProvider.getRefreshTokenExpiredAt(refreshToken).isBefore(Instant.now())) {
            refreshTokenRepository.softDeleteByOpaqueIdAndJti(opaqueId, jti, Instant.now())
            throw JwtException(JwtExceptionCode.EXPIRED)
        }

        // AccessToken, RefreshToken 재발급
        val newAccessToken = jwtProvider.createAccessToken(
            opaqueId = opaqueId,
            role = Role.MEMBER,
            extraClaims = mapOf("deviceId" to deviceId)
        )
        val newRefreshToken = jwtProvider.createRefreshToken(opaqueId = opaqueId)
        val newJti = jwtProvider.getJti(newRefreshToken)

        // 기존 RefreshToken soft delete 처리
        refreshTokenRepository.softDeleteByOpaqueIdAndJti(opaqueId, jti, Instant.now())

        // 새 refreshToken 저장
        val member = memberRepository.findByOpaqueId(opaqueId).get()
        val newRefreshTokenEntity = RefreshTokenEntity.of(member, newJti, opaqueId, deviceId)
        refreshTokenRepository.save(newRefreshTokenEntity)

        return TokenResult(newAccessToken, newRefreshToken)
    }

}
