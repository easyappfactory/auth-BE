package com.wq.auth.api.domain.member

import com.wq.auth.api.domain.auth.AuthProviderRepository
import com.wq.auth.api.domain.auth.RefreshTokenRepository
import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.domain.member.entity.MemberWithdrawalAuditEntity
import com.wq.auth.api.domain.member.error.MemberException
import com.wq.auth.api.domain.member.error.MemberExceptionCode
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant

@Service
class MemberService(
    private val memberRepository: MemberRepository,
    private val authProviderRepository: AuthProviderRepository,
    private val refreshTokenRepository: RefreshTokenRepository,
    private val memberWithdrawalAuditRepository: MemberWithdrawalAuditRepository,
    ) {

    companion object {
        private val log = LoggerFactory.getLogger(MemberService::class.java)
    }

    data class UserInfoResult(
        val userId: String,
        val nickname: String,
        val email: String,
        val phoneNumber: String?,
        val providers: List<ProviderType>,
    )

    /**
     * API Gateway introspect용. 회원의 대표 연동 제공자 하나를 반환한다.
     * 연동된 provider 목록 중 첫 번째를 사용한다. 회원 없거나 연동 없으면 null.
     */
    @Transactional(readOnly = true)
    fun getPrimaryProvider(opaqueId: String): ProviderType? {
        val member = memberRepository.findByOpaqueId(opaqueId).orElse(null) ?: return null
        val providers = authProviderRepository.findByMember(member)
        return providers.firstOrNull()?.providerType
    }

    @Transactional(readOnly = true)
    fun getUserInfo(opaqueId: String): UserInfoResult {
        log.debug("[MemberService] getUserInfo - opaqueId={}", opaqueId)

        val member = memberRepository.findByOpaqueId(opaqueId)
            .orElseThrow {
                log.warn("[MemberService] 회원 없음 - opaqueId={}", opaqueId)
                MemberException(MemberExceptionCode.USER_INFO_RETRIEVE_FAILED)
            }

        val authProviders = authProviderRepository.findByMember(member)
        if (authProviders.isEmpty()) {
            log.warn("[MemberService] authProvider 없음 - opaqueId={}, memberId={}", opaqueId, member.id)
            throw MemberException(MemberExceptionCode.USER_INFO_RETRIEVE_FAILED)
        }

        val email = member.primaryEmail
        if (email == null) {
            log.error("[MemberService] primaryEmail이 null - opaqueId={}, memberId={}", opaqueId, member.id)
        }
        val providers = authProviders.map { it.providerType }

        //TODO
        //전화번호 로그인 추가시 null처리 필요
        return UserInfoResult(
            userId = member.opaqueId,
            nickname = member.nickname,
            email = email!!,
            phoneNumber = member.phoneNumber,
            providers = providers
        )
    }

    fun getAll(): List<MemberEntity> = memberRepository.findAll()

    fun getById(id: Long): MemberEntity? = memberRepository.findById(id).orElse(null)

    fun create(member: MemberEntity): MemberEntity = memberRepository.save(member)

    @Transactional
    fun withdraw(opaqueId: String, sourceClient: String?) {
        val member = memberRepository.findByOpaqueId(opaqueId).orElse(null)
        if (member == null) {
            log.warn("[MemberService] 이미 탈퇴한 회원 - opaqueId={}", opaqueId)
            return
        }

        memberWithdrawalAuditRepository.save(
            MemberWithdrawalAuditEntity(
                opaqueId = opaqueId,
                withdrawnAt = Instant.now(),
                sourceClient = sourceClient,
            )
        )

        // 회원 행은 바로 아래에서 삭제되지만, 삭제 트랜잭션 커밋 전후의 짧은 창과
        // 게이트웨이 introspect 캐시 때문에 폐기 시각도 함께 남긴다.
        // 삭제된 이후의 판정은 introspect 의 "회원 부재 = 폐기" 규칙이 담당한다.
        member.revokeTokens()

        refreshTokenRepository.deleteByMember(member)
        authProviderRepository.deleteByMember(member)
        memberRepository.delete(member)

        log.info("[MemberService] 회원 탈퇴 완료 - opaqueId={}, sourceClient={}", opaqueId, sourceClient)
    }

    fun updateNickname(id: Long, newNickname: String): MemberEntity? {
        val member = memberRepository.findById(id).orElse(null)
        member?.let {
            it.nickname = newNickname
            return memberRepository.save(it)
        }
        return null
    }

}
