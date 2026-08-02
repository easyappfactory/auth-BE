package com.wq.auth.api.domain.member

import com.wq.auth.api.domain.member.entity.MemberWithdrawalAuditEntity
import org.springframework.data.jpa.repository.JpaRepository

interface MemberWithdrawalAuditRepository : JpaRepository<MemberWithdrawalAuditEntity, Long>
