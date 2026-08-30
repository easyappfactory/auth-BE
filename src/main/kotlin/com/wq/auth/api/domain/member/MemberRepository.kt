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
     * 토큰 폐기 판정에 필요한 상태만 조회합니다.
     *
     * 세 가지 상황을 구분해야 합니다.
     *   ① **결과가 `null`** — 회원 행이 없음 = 탈퇴(hard delete)한 계정
     *   ② **`isDeleted = true`** — soft delete 된 계정 (계정 병합으로 흡수된 회원)
     *   ③ **`tokensInvalidBefore`** — 로그아웃·탈퇴·RT 재사용 탐지 시각
     *
     * 스칼라 값 하나만 뽑으면 ①과 "폐기 이력 없음"이 둘 다 `null` 로 뭉개져 구분할 수 없습니다.
     * 판정 로직은 [MemberRevocationState] 를 받아 서비스에서 수행합니다 —
     * 조건을 JPQL 에 넣으면 단위 테스트가 분기를 검증할 수 없기 때문입니다.
     *
     * 엔티티를 통째로 로딩하지 않는 이유는 이 쿼리가 introspect 핫패스에서 돌기 때문입니다.
     * opaque_id 에는 unique 인덱스(idx_member_opaque_id)가 있습니다.
     */
    @Query(
        """
        select new com.wq.auth.api.domain.member.MemberRevocationState(m.isDeleted, m.tokensInvalidBefore)
        from MemberEntity m
        where m.opaqueId = :opaqueId
        """
    )
    fun findRevocationStateByOpaqueId(@Param("opaqueId") opaqueId: String): MemberRevocationState?
}