package com.wq.auth.api.domain.member.entity

import com.wq.auth.shared.entity.BaseEntity
import com.github.f4b6a3.uuid.UuidCreator
import jakarta.persistence.*
import java.time.LocalDateTime

@Entity
@Table(
    name = "member",
    indexes = [
        Index(name = "idx_member_opaque_id", columnList = "opaque_id", unique = true)
    ]
)
open class MemberEntity protected constructor(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long = 0,

    @Column(name = "primary_email", nullable = true)
    val primaryEmail: String? = null,

    @Column(name = "phone_number", length = 20, nullable = true)
    val phoneNumber: String? = null,

    @Column(name = "opaque_id", nullable = false, unique = true, length = 36)
    val opaqueId: String,

    @Column(nullable = false, length = 100)
    var nickname: String,

    @Column(name = "is_email_verified", nullable = false)
    var isEmailVerified: Boolean = false,

    @Column(name = "last_login_at")
    var lastLoginAt: LocalDateTime? = null,

    //TODO
    //회원 삭제 기능 개발시 모든 쿼리 is_deleted 확인 추가
    //is_deleted -> deleted_at?
    @Column(name = "is_deleted", nullable = false)
    var isDeleted: Boolean = false,

) : BaseEntity() {

    companion object {
        fun createEmailVerifiedMember(nickname: String, email: String) =
            MemberEntity(
                nickname = nickname,
                isEmailVerified = true,
                primaryEmail = email,
                opaqueId = UuidCreator.getTimeOrdered().toString(),
                lastLoginAt = LocalDateTime.now(),
            )

        fun create(
            nickname: String,
        ): MemberEntity {
            require(nickname.isNotBlank()) { "닉네임은 필수입니다" }
            require(nickname.length <= 100) { "닉네임은 100자를 초과할 수 없습니다" }

            return MemberEntity(
                opaqueId = UuidCreator.getTimeOrdered().toString(),
                nickname = nickname.trim(),
            )
        }

        fun createSocialMember(
            nickname: String,
            isEmailVerified: Boolean = true,
            primaryEmail: String,
        ): MemberEntity {
            require(nickname.isNotBlank()) { "닉네임은 필수입니다" }
            require(nickname.length <= 100) { "닉네임은 100자를 초과할 수 없습니다" }

            return MemberEntity(
                opaqueId = UuidCreator.getTimeOrdered().toString(),
                nickname = nickname.trim(),
                isEmailVerified = isEmailVerified,
                primaryEmail = primaryEmail
            )
        }
    }

    /**
     * 이메일 인증 완료 처리
     */
    fun verifyEmail() {
        this.isEmailVerified = true
    }

    /**
     * 최근 로그인 시간 업데이트
     */
    fun updateLastLoginAt() {
        this.lastLoginAt = LocalDateTime.now()
    }

    /**
     * 회원을 soft delete 처리합니다.
     * 실제로 데이터를 삭제하지 않고 isDeleted 플래그만 변경합니다.
     */
    fun softDelete() {
        this.isDeleted = true
    }

    override fun toString(): String {
        return "MemberEntity(id=$id, opaqueId='$opaqueId', nickname='$nickname')"
    }
}