package com.wq.auth.api.domain.member.entity

import jakarta.persistence.*
import java.time.Instant

@Entity
@Table(name = "member_withdrawal_audit")
class MemberWithdrawalAuditEntity(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long = 0,

    @Column(name = "opaque_id", nullable = false, length = 36)
    val opaqueId: String,

    @Column(name = "withdrawn_at", nullable = false)
    val withdrawnAt: Instant,

    @Column(name = "source_client", nullable = true, length = 50)
    val sourceClient: String? = null,
)
