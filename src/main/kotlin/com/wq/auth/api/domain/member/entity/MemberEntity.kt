package com.wq.auth.api.domain.member.entity

import com.wq.auth.shared.entity.BaseEntity
import com.github.f4b6a3.uuid.UuidCreator
import jakarta.persistence.*
import org.hibernate.annotations.DynamicUpdate
import java.time.Instant
import java.time.LocalDateTime

/**
 * 회원 엔티티.
 *
 * `@DynamicUpdate` 인 이유: 로그인 트랜잭션이 `last_login_at` 하나만 바꾸는데
 * 전체 컬럼을 쓰면, 동시에 일어난 로그아웃이 기록한 `tokens_invalid_before` 를
 * 로그인 시작 시점에 읽은 낡은 값으로 덮어쓸 수 있다. 변경된 컬럼만 UPDATE 한다.
 */
@Entity
@DynamicUpdate
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
    var phoneNumber: String? = null,

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

    /**
     * 이 시각 이전(=이하)에 발급된 토큰은 폐기된 것으로 본다.
     * 로그아웃·탈퇴·RT 재사용 탐지 시 기록한다. null 이면 폐기 이력 없음.
     *
     * 세션 전체를 stateful 하게 관리하지 않기 위해 사용자당 타임스탬프 하나만 둔다.
     * 실제 판정은 introspect 가 토큰의 iat 와 비교해 수행한다.
     */
    @Column(name = "tokens_invalid_before", nullable = true)
    var tokensInvalidBefore: Instant? = null,

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
            phoneNumber: String? = null,
        ): MemberEntity {
            require(nickname.isNotBlank()) { "닉네임은 필수입니다" }
            require(nickname.length <= 100) { "닉네임은 100자를 초과할 수 없습니다" }

            return MemberEntity(
                opaqueId = UuidCreator.getTimeOrdered().toString(),
                nickname = nickname.trim(),
                isEmailVerified = isEmailVerified,
                primaryEmail = primaryEmail,
                phoneNumber = phoneNumber,
                lastLoginAt = LocalDateTime.now(),
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
     * 전화번호 업데이트
     */
    fun updatePhoneNumber(phoneNumber: String) {
        this.phoneNumber = phoneNumber
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

    /**
     * 이 회원이 지금까지 발급받은 토큰을 모두 폐기 대상으로 표시합니다.
     *
     * AT 는 만료(30분)까지 서명이 유효하므로 RT 폐기만으로는 즉시 로그아웃이 되지 않습니다.
     * 이 시각을 남겨 두면 introspect 가 iat 를 비교해 옛 AT 를 거부합니다.
     */
    fun revokeTokens(at: Instant = Instant.now()) {
        this.tokensInvalidBefore = at
    }

    override fun toString(): String {
        return "MemberEntity(id=$id, opaqueId='$opaqueId', nickname='$nickname')"
    }
}