package com.wq.auth.api.domain.auth

import com.wq.auth.api.domain.auth.entity.AuthProviderEntity
import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.domain.auth.entity.ProviderType
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.transaction.annotation.Transactional

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
    ): AuthProviderEntity?

    @Modifying
    @Transactional
    fun deleteByMember(member: MemberEntity)
}