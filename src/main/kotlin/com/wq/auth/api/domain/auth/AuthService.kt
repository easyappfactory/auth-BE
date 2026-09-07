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
import com.wq.auth.api.domain.member.error.MemberException
import com.wq.auth.api.domain.member.error.MemberExceptionCode
import com.wq.auth.security.jwt.JwtProvider
import com.wq.auth.security.jwt.error.JwtException
import com.wq.auth.security.jwt.error.JwtExceptionCode
import com.wq.auth.shared.alert.SecurityAlertNotifier
import com.wq.auth.shared.utils.NicknameGenerator
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Duration
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
    private val securityAlertNotifier: SecurityAlertNotifier,

    /**
     * RT 재사용 유예 창(초).
     *
     * 이 시간 안에 회전된 RT 가 다시 오면 **도난이 아니라 동시 요청·재시도**로 본다.
     * 0 으로 두면 유예 없이 즉시 도난으로 판정한다(정상 사용자 로그아웃 위험).
     * 운영 로그를 보고 조정할 수 있도록 설정값으로 뺐다.
     */
    @Value("\${app.auth.refresh-reuse-grace-seconds:30}")
    private val refreshReuseGraceSeconds: Long = 30,
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
            
            // 같은 트랜잭션 안에서 dirty checking 으로 커밋된다.
            existingUser.updateLastLoginAt()

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

    /**
     * 폐기된 토큰이면 [JwtException]을 던집니다. 유효하면 조용히 반환합니다.
     *
     * 세 가지를 거릅니다. 서명이 유효해도 그 신원이 이미 없어졌을 수 있기 때문입니다.
     *   ① **회원 행이 없음** = 탈퇴(hard delete)한 계정. `tokens_invalid_before` 를 읽을
     *      수조차 없으므로 행 부재 자체를 폐기 신호로 씁니다.
     *   ② **soft delete 된 계정** = 계정 병합으로 흡수된 회원([MemberConnector]).
     *      행은 남지만 그 신원으로는 더 이상 로그인할 수 없으므로 토큰도 무효여야 합니다.
     *   ③ **iat <= tokens_invalid_before** = 로그아웃·탈퇴·RT 재사용 탐지 이전 발급분.
     *
     * ②는 병합 시점에도 [MemberEntity.revokeTokens] 로 기록하지만, 여기서도 확인합니다.
     * 앞으로 soft delete 를 쓰는 코드가 기록을 빠뜨려도 이 방어선이 막습니다.
     *
     * iat 는 초 단위 정밀도라 같은 초에 발급된 토큰도 거부해야 합니다 —
     * 그래서 `isAfter` 의 부정으로 비교합니다.
     *
     * **성능** — introspect 의 AT 유효 경로에서 호출되므로 DB 읽기가 하나 추가됩니다.
     * opaque_id unique 인덱스 단일 조회이고 컬럼 두 개만 읽습니다. 게이트웨이
     * introspect 캐시가 앞단에서 대부분을 막아 실제로는 캐시 미스에서만 발생합니다.
     */
    fun assertTokenNotRevoked(token: String, opaqueId: String) {
        val state = memberRepository.findRevocationStateByOpaqueId(opaqueId)
        if (state == null) {
            log.info { "폐기된 토큰: 회원 없음(탈퇴) opaqueId=$opaqueId" }
            throw JwtException(JwtExceptionCode.EXPIRED)
        }
        if (state.isDeleted) {
            log.info { "폐기된 토큰: 삭제된 계정(병합 등) opaqueId=$opaqueId" }
            throw JwtException(JwtExceptionCode.EXPIRED)
        }
        val invalidBefore = state.tokensInvalidBefore ?: return   // 폐기 이력 없음 — 정상
        if (!jwtProvider.getIssuedAt(token).isAfter(invalidBefore)) {
            log.info { "폐기된 토큰: 폐기 시각 이전 발급 opaqueId=$opaqueId" }
            throw JwtException(JwtExceptionCode.EXPIRED)
        }
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
            // RT 만 지우면 AT 는 만료(30분)까지 그대로 유효하다.
            // 폐기 시각을 남겨 introspect 가 옛 AT 를 거부하게 한다.
            // @Transactional 이라 dirty checking 으로 반영된다 — save() 불필요.
            memberRepository.findByOpaqueId(opaqueId).ifPresent { it.revokeTokens() }
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

        // active 가 없는 이유가 세 가지다. 구분해야 도난만 골라낼 수 있다.
        if (refreshTokenRepository.findActiveByOpaqueIdAndJti(opaqueId, jti) == null) {
            val used = refreshTokenRepository.findByOpaqueIdAndJtiIncludingDeleted(opaqueId, jti)
                // ① 존재한 적 없는 jti — 잘못된 토큰. 패밀리는 건드리지 않는다.
                ?: throw JwtException(JwtExceptionCode.MALFORMED)

            val rotatedAt = used.deletedAt
            val withinGrace = rotatedAt != null &&
                Duration.between(rotatedAt, Instant.now()).seconds <= refreshReuseGraceSeconds

            if (withinGrace) {
                // ② 방금 회전된 jti — 동시 요청이나 네트워크 재시도다.
                //
                // AT 잔여 5분 미만이면 모든 introspect 가 갱신을 타는데(AT 수명 30분),
                // 그 구간에 페이지가 API 를 여러 개 동시 호출하면 같은 RT 로 갱신이 겹친다.
                // 여기서 실패시키면 silentRefresh 가 쿠키를 지워(clearAuthCookies)
                // **정상 사용자가 로그아웃된다.** 그래서 아래 정상 발급 경로로 이어간다.
                //
                // 대가: 유예 창 안에서는 도난 토큰도 통과한다. 다만 공격자가 정상 회전
                // 직후 몇 초 안에 써야 하므로 창이 매우 좁고, 그 대가로 정상 사용자가
                // 주기적으로 튕기는 문제를 막는다.
                log.info { "RT 재사용(유예 창 내) — 동시 요청·재시도로 판단: opaqueId=$opaqueId jti=$jti" }
            } else {
                // ③ 한참 전에 폐기된 jti 가 다시 나타났다 = 도난 정황.
                // 회전만 하고 탐지가 없으면, 공격자가 먼저 쓴 경우 공격자는 새 토큰 쌍을 얻고
                // 정상 사용자만 로그아웃되며 아무도 도난 사실을 모른다.
                // 계정이 탈취된 상황이므로 정상 사용자도 재로그인시키는 것이 옳다.
                log.warn { "RT 재사용 감지(도난 정황): opaqueId=$opaqueId jti=$jti rotatedAt=$rotatedAt" }
                refreshTokenRepository.softDeleteAllByOpaqueId(opaqueId, Instant.now())
                memberRepository.findByOpaqueId(opaqueId).ifPresent { it.revokeTokens() }
                // 로그에만 남기면 아무도 모른다. 계정 탈취 정황이므로 운영 채널로 알린다.
                // 비동기이고 실패해도 예외를 내보내지 않으므로 이 경로를 지연시키지 않는다.
                securityAlertNotifier.refreshTokenReuseDetected(opaqueId, jti, rotatedAt)
                throw JwtException(JwtExceptionCode.MALFORMED)
            }
        }

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
