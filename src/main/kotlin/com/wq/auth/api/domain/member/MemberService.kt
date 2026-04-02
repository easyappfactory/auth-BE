package com.wq.auth.api.domain.member

import com.wq.auth.api.domain.auth.AuthProviderRepository
import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.domain.member.error.MemberException
import com.wq.auth.api.domain.member.error.MemberExceptionCode
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class MemberService(
    private val memberRepository: MemberRepository,
    private val authProviderRepository: AuthProviderRepository,
    ) {

    data class UserInfoResult(
        val userId: String,
        val nickname: String,
        val email: String,
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
        val member = memberRepository.findByOpaqueId(opaqueId)
            .orElseThrow { MemberException(MemberExceptionCode.USER_INFO_RETRIEVE_FAILED)}

        val authProviders = authProviderRepository.findByMember(member)
        if (authProviders.isEmpty()) {
            throw MemberException(MemberExceptionCode.USER_INFO_RETRIEVE_FAILED)
        }

        val email = member.primaryEmail
        val providers = authProviders.map { it.providerType }

        //TODO
        //전화번호 로그인 추가시 null처리 필요
        return UserInfoResult(
            userId = member.opaqueId,
            nickname = member.nickname,
            email = email!!,
            providers = providers
        )
    }

    fun getAll(): List<MemberEntity> = memberRepository.findAll()

    fun getById(id: Long): MemberEntity? = memberRepository.findById(id).orElse(null)

    fun create(member: MemberEntity): MemberEntity = memberRepository.save(member)

    fun delete(id: Long) = memberRepository.deleteById(id)

    fun updateNickname(id: Long, newNickname: String): MemberEntity? {
        val member = memberRepository.findById(id).orElse(null)
        member?.let {
            it.nickname = newNickname
            return memberRepository.save(it)
        }
        return null
    }

}
