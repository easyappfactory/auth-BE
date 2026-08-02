package com.wq.auth.unit

import com.wq.auth.api.domain.auth.AuthProviderRepository
import com.wq.auth.api.domain.auth.RefreshTokenRepository
import com.wq.auth.api.domain.member.MemberRepository
import com.wq.auth.api.domain.member.MemberService
import com.wq.auth.api.domain.member.MemberWithdrawalAuditRepository
import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.domain.member.entity.MemberWithdrawalAuditEntity
import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import org.mockito.ArgumentCaptor
import org.mockito.kotlin.*
import java.util.Optional

class MemberWithdrawServiceTest : DescribeSpec({

    lateinit var memberRepository: MemberRepository
    lateinit var authProviderRepository: AuthProviderRepository
    lateinit var refreshTokenRepository: RefreshTokenRepository
    lateinit var memberWithdrawalAuditRepository: MemberWithdrawalAuditRepository
    lateinit var memberService: MemberService

    beforeEach {
        memberRepository = mock()
        authProviderRepository = mock()
        refreshTokenRepository = mock()
        memberWithdrawalAuditRepository = mock()
        memberService = MemberService(
            memberRepository,
            authProviderRepository,
            refreshTokenRepository,
            memberWithdrawalAuditRepository,
        )
    }

    describe("withdraw - 회원 탈퇴") {

        it("정상적인 opaqueId가 주어지면 자식 먼저 부모 나중 순서로 삭제한다") {
            // given
            val opaqueId = "test-opaque-id"
            val mockMember = mock<MemberEntity>()
            whenever(mockMember.opaqueId).thenReturn(opaqueId)
            whenever(memberRepository.findByOpaqueId(opaqueId)).thenReturn(Optional.of(mockMember))

            val auditCaptor = ArgumentCaptor.forClass(MemberWithdrawalAuditEntity::class.java)
            whenever(memberWithdrawalAuditRepository.save(any<MemberWithdrawalAuditEntity>())).thenAnswer { it.arguments[0] }

            // when
            memberService.withdraw(opaqueId, "app")

            // then
            verify(memberWithdrawalAuditRepository).save(auditCaptor.capture())
            val audit = auditCaptor.value
            audit.opaqueId shouldBe opaqueId
            audit.sourceClient shouldBe "app"

            val inOrder = inOrder(memberWithdrawalAuditRepository, refreshTokenRepository, authProviderRepository, memberRepository)
            inOrder.verify(memberWithdrawalAuditRepository).save(any<MemberWithdrawalAuditEntity>())
            inOrder.verify(refreshTokenRepository).deleteByMember(mockMember)
            inOrder.verify(authProviderRepository).deleteByMember(mockMember)
            inOrder.verify(memberRepository).delete(mockMember)
        }

        it("존재하지 않는 opaqueId가 주어지면 예외 없이 멱등 성공한다") {
            // given
            val opaqueId = "already-withdrawn-id"
            whenever(memberRepository.findByOpaqueId(opaqueId)).thenReturn(Optional.empty())

            // when - 예외가 발생하지 않아야 함
            memberService.withdraw(opaqueId, "app")

            // then
            verify(memberRepository).findByOpaqueId(opaqueId)
            verify(memberWithdrawalAuditRepository, never()).save(any<MemberWithdrawalAuditEntity>())
            verify(refreshTokenRepository, never()).deleteByMember(any())
            verify(authProviderRepository, never()).deleteByMember(any())
            verify(memberRepository, never()).delete(any<MemberEntity>())
        }

        it("sourceClient가 null이어도 정상 처리된다") {
            // given
            val opaqueId = "test-opaque-id"
            val mockMember = mock<MemberEntity>()
            whenever(mockMember.opaqueId).thenReturn(opaqueId)
            whenever(memberRepository.findByOpaqueId(opaqueId)).thenReturn(Optional.of(mockMember))
            whenever(memberWithdrawalAuditRepository.save(any<MemberWithdrawalAuditEntity>())).thenAnswer { it.arguments[0] }

            // when
            memberService.withdraw(opaqueId, null)

            // then
            val captor = ArgumentCaptor.forClass(MemberWithdrawalAuditEntity::class.java)
            verify(memberWithdrawalAuditRepository).save(captor.capture())
            captor.value.sourceClient shouldBe null
        }
    }
})
