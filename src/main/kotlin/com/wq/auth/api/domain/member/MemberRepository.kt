package com.wq.auth.api.domain.member

import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.domain.auth.entity.ProviderType
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import org.springframework.stereotype.Repository
import java.time.Instant
import java.util.*

@Repository
interface MemberRepository : JpaRepository<MemberEntity, Long> {

    fun existsByNickname(nickname: String): Boolean
    fun findByOpaqueId(opaqueId: String): Optional<MemberEntity>

    @Query("""
        SELECT m FROM MemberEntity m 
        JOIN AuthProviderEntity ap ON m.id = ap.member.id 
        WHERE ap.providerId = :providerId 
        AND ap.providerType = :providerType 
        AND m.isDeleted = false
    """)
    fun findByProviderIdAndProviderType(
        @Param("providerId") providerId: String,
        @Param("providerType") providerType: ProviderType
    ): Optional<MemberEntity>

    fun findByOpaqueIdAndIsDeletedFalse(opaqueId: String): Optional<MemberEntity>

    /**
     * 폐기 판정에 필요한 최소 정보만 조회합니다.
     *
     * **반환형이 `Instant?` 가 아니라 `List<Instant?>` 인 이유** —
     * 스칼라 프로젝션에서 `Instant?` 를 쓰면 아래 두 상황이 모두 `null` 로 뭉개져 구분할 수 없습니다.
     *   ① 회원 행 자체가 없음 = **탈퇴한 계정** (탈퇴는 hard delete 입니다)
     *   ② 회원은 있으나 폐기 이력이 없음 = 정상
     * ①을 폐기로 판정해야 탈퇴 직후의 옛 AT 를 막을 수 있으므로 이 구분이 필수입니다.
     * 리스트가 비었으면 ①, 원소가 있고 그 값이 null 이면 ②입니다.
     *
     * 엔티티를 통째로 로딩하지 않는 이유는 이 쿼리가 introspect 핫패스에서 돌기 때문입니다.
     * opaque_id 에는 unique 인덱스(idx_member_opaque_id)가 있습니다.
     */
    @Query("select m.tokensInvalidBefore from MemberEntity m where m.opaqueId = :opaqueId")
    fun findTokensInvalidBeforeByOpaqueId(@Param("opaqueId") opaqueId: String): List<Instant?>
}