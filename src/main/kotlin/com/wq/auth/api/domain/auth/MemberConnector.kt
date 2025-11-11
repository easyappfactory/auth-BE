package com.wq.auth.api.domain.auth

import com.wq.auth.api.domain.auth.entity.AuthProviderEntity
import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.auth.error.AuthException
import com.wq.auth.api.domain.auth.error.AuthExceptionCode
import com.wq.auth.api.domain.member.MemberRepository
import com.wq.auth.api.domain.member.entity.MemberEntity
import org.springframework.transaction.annotation.Transactional
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.stereotype.Component

@Component
@Transactional
class MemberConnector(
    private val memberRepository: MemberRepository,
    private val authProviderRepository: AuthProviderRepository,
) {

    private val log = KotlinLogging.logger {}

    /**
     * 계정 연동 공통 로직
     *
     * @param currentMember 현재 로그인된 회원
     * @param providerType 연동할 제공자 타입
     * @param providerId 제공자 ID (이메일의 경우 null)
     * @param email 이메일
     * @param findExistingProvider 기존 AuthProvider 조회 함수
     */
    fun linkAccountInternal(
        currentMember: MemberEntity,
        providerType: ProviderType,
        providerId: String?,
        email: String,
        findExistingProvider: () -> AuthProviderEntity?
    ) {
        // 이미 해당 계정이 다른 회원과 연동되어 있는지 확인
        findExistingProvider()?.let { provider ->
            val linkedMember = provider.member

            // 이미 현재 회원과 연동된 경우
            if (linkedMember.opaqueId == currentMember.opaqueId) {
                log.info { "이미 연동된 계정입니다: ${currentMember.opaqueId}" }
                return
            }

            // 다른 회원과 연동된 경우 -> 회원 병합
            log.info {
                "연동 계정이 존재합니다. 회원 병합 시작: ${currentMember.opaqueId} <- ${linkedMember.opaqueId}"
            }
            mergeMemberAccounts(currentMember, linkedMember, providerType)
        } ?: run {
            // 연동 계정이 없는 경우 -> AuthProvider만 추가
            log.info { "새로운 계정 연동: ${currentMember.opaqueId} -> $providerType" }
            val authProvider = AuthProviderEntity(
                member = currentMember,
                providerType = providerType,
                providerId = providerId,
                email = email
            )
            authProviderRepository.save(authProvider)
        }

        // 마지막 로그인 시간 업데이트
        currentMember.updateLastLoginAt()
    }

    /**
     * 두 회원을 병합합니다.
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
    fun mergeMemberAccounts(
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