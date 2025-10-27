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

    ) {
    private val log = KotlinLogging.logger {}

    data class TokenResult(
        val accessToken: String,
        val refreshToken: String,
    )

    @Transactional
    fun emailLogin(email: String, deviceId: String?): TokenResult {
        val existingUser =
            authProviderRepository.findByEmailAndProviderType(email, ProviderType.EMAIL).map { it.member }.orElse(null)

        // 신규 사용자면 회원가입 진행
        if (existingUser == null) {
            return signUp(email, deviceId)
        }

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
        val existingAuthProvider = authProviderRepository.findByEmailAndProviderType(
            request.email,
            ProviderType.EMAIL,
        )

        //TODO
        //memberConnector 분리 + 소셜도 사용
        if (existingAuthProvider.isPresent) {
            val linkedMember = existingAuthProvider.get().member

            // 이미 현재 회원과 연동된 경우
            if (linkedMember.opaqueId == currentMember.opaqueId) {
                log.info { "이미 연동된 계정입니다: ${currentMember.opaqueId}" }
                return
            }

            // 다른 회원과 연동된 경우 -> 회원 병합
            log.info { "연동 계정이 존재합니다. 회원 병합 시작: ${currentMember.opaqueId} <- ${linkedMember.opaqueId}" }
            mergeMemberAccounts(currentMember, linkedMember, ProviderType.EMAIL)
        } else {
            // 연동 계정이 없는 경우 -> AuthProvider만 추가
            log.info { "이메일 연동: ${currentMember.opaqueId} -> EMAIL" }
            val authProvider = AuthProviderEntity(
                member = currentMember,
                providerType = ProviderType.EMAIL,
                providerId = null,
                email = request.email
            )
            authProviderRepository.save(authProvider)
        }

        // 마지막 로그인 시간 업데이트
        currentMember.updateLastLoginAt()

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
        refreshTokenRepository.findActiveByOpaqueIdAndJti(opaqueId, jti)?: throw JwtException(JwtExceptionCode.MALFORMED)

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

    /**
     * 두 회원을 병합합니다.
     * LinkProvider의 mergeMemberAccounts()와 동일합니다.
     *
     * 병합 규칙:
     * - 최초 가입한 회원(currentMember)의 정보를 우선 사용
     * - 새로 연동된 회원(linkedMember)은 soft delete 처리
     * - 새로 연동된 회원의 AuthProvider를 현재 회원으로 이전
     *
     * @param currentMember 현재 로그인된 회원 (유지될 회원)
     * @param linkedMember 연동하려는 계정으로 이미 가입된 회원 (삭제될 회원)
     * @param providerType 연동하려는 로그인 제공자 타입
     */
    @Transactional
    open fun mergeMemberAccounts(
        currentMember: MemberEntity,
        linkedMember: MemberEntity,
        providerType: ProviderType
    ) {
        log.info { "회원 병합 시작: ${currentMember.opaqueId} <- ${linkedMember.opaqueId}" }

        // 연동된 회원의 모든 AuthProvider를 조회
        val linkedAuthProviders = authProviderRepository.findByMember(linkedMember)

        if (linkedAuthProviders.isEmpty()) {
            log.warn { "병합할 AuthProvider가 없습니다: ${linkedMember.opaqueId}" }
            throw AuthException(AuthExceptionCode.AUTH_PROVIDER_NOT_FOUND)
        }

        // 현재 회원이 이미 가지고 있는 ProviderType 목록 조회 (중복 방지)
        val currentProviderTypes = authProviderRepository.findByMember(currentMember)
            .map { it.providerType }
            .toSet()

        //TODO
        // 더 이전에 가입한 사용자를 남겨야함
        // 현재 로그인된 사용자가 지워질 경우,
        // 이렇게 바꾸면, service에서 member 정보를 바꾸고 token도 새로 발급해줘야함
        // 연동된 회원의 모든 AuthProvider를 현재 회원으로 이전
        linkedAuthProviders.forEach { authProvider ->
            // 현재 회원이 이미 동일한 ProviderType을 가지고 있는 경우 스킵
            if (currentProviderTypes.contains(authProvider.providerType)) {
                log.warn {
                    "현재 회원이 이미 ${authProvider.providerType}를 가지고 있습니다.: ${currentMember.opaqueId}"
                }

                //TODO
                // 중복된 AuthProvider는 삭제 -> soft delete
                authProviderRepository.delete(authProvider)
            } else {
                // AuthProvider의 member를 현재 회원으로 변경
                authProvider.changeMember(currentMember)
                authProviderRepository.save(authProvider)
                log.info {
                    "${authProvider.providerType} AuthProvider 이전 완료: ${linkedMember.opaqueId} -> ${currentMember.opaqueId}"
                }
            }
        }

        // 연동된 회원을 soft delete 처리
        linkedMember.softDelete()
        memberRepository.save(linkedMember)

        log.info { "회원 병합 완료: ${currentMember.opaqueId} <- ${linkedMember.opaqueId} (deleted)" }
    }

}
