package com.wq.auth.api.domain.auth

import com.wq.auth.api.domain.auth.entity.AuthProviderEntity
import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.domain.auth.entity.ProviderType
import org.springframework.data.jpa.repository.JpaRepository
import java.util.Optional

interface AuthProviderRepository : JpaRepository<AuthProviderEntity, Long> {
    fun findByEmailAndProviderType(email: String, providerType: ProviderType): AuthProviderEntity?

    fun findByProviderIdAndProviderType(
        providerId: String,
        providerType: ProviderType
    ): AuthProviderEntity?

    fun findByMember(member: MemberEntity): List<AuthProviderEntity>

    fun findByMemberAndProviderType(
        member: MemberEntity,
        providerType: ProviderType
    ): Optional<AuthProviderEntity>
}