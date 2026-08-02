package com.wq.auth.api.domain.auth

import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.domain.auth.entity.RefreshTokenEntity
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import org.springframework.transaction.annotation.Transactional
import java.time.Instant

interface RefreshTokenRepository : JpaRepository<RefreshTokenEntity, Long> {
    fun findByMember(member: MemberEntity): RefreshTokenEntity?

    // Soft delete 메서드들
    @Modifying
    @Transactional
    @Query("UPDATE RefreshTokenEntity r SET r.deletedAt = :deletedAt WHERE r.member.opaqueId = :opaqueId AND r.jti = :jti AND r.deletedAt IS NULL")
    fun softDeleteByOpaqueIdAndJti(@Param("opaqueId") opaqueId: String, @Param("jti") jti: String, @Param("deletedAt") deletedAt: Instant): Int
    
    @Modifying
    @Transactional
    @Query("UPDATE RefreshTokenEntity r SET r.deletedAt = :deletedAt WHERE r.member = :member AND r.deviceId = :deviceId AND r.deletedAt IS NULL")
    fun softDeleteByMemberAndDeviceId(@Param("member") member: MemberEntity, @Param("deviceId") deviceId: String?, @Param("deletedAt") deletedAt: Instant): Int
    
    // 삭제되지 않은 토큰만 조회
    @Query("SELECT r FROM RefreshTokenEntity r WHERE r.member.opaqueId = :opaqueId AND r.jti = :jti AND r.deletedAt IS NULL")
    fun findActiveByOpaqueIdAndJti(@Param("opaqueId") opaqueId: String, @Param("jti") jti: String): RefreshTokenEntity?
    
    @Query("SELECT r FROM RefreshTokenEntity r WHERE r.member = :member AND r.deviceId = :deviceId AND r.deletedAt IS NULL")
    fun findActiveByMemberAndDeviceId(@Param("member") member: MemberEntity, @Param("deviceId") deviceId: String?): RefreshTokenEntity?

    @Modifying
    @Transactional
    fun deleteByMember(member: MemberEntity)

}