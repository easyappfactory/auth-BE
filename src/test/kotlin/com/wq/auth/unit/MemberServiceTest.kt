package com.wq.auth.unit

import com.wq.auth.api.domain.auth.AuthProviderRepository
import com.wq.auth.api.domain.auth.entity.AuthProviderEntity
import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.member.MemberRepository
import com.wq.auth.api.domain.member.MemberService
import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.domain.member.error.MemberException
import com.wq.auth.api.domain.member.error.MemberExceptionCode
import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.assertions.throwables.shouldThrow
import org.mockito.kotlin.*
import java.util.Optional

class MemberServiceTest : DescribeSpec({

    lateinit var memberRepository: MemberRepository
    lateinit var authProviderRepository: AuthProviderRepository
    lateinit var memberService: MemberService

    beforeEach {
        memberRepository = mock<MemberRepository>()
        authProviderRepository = mock<AuthProviderRepository>()
        memberService = MemberService(memberRepository, authProviderRepository)
    }

    describe("사용자 정보 조회 테스트") {

        it("정상적인 opaqueId가 주어지면 사용자 정보를 반환한다") {
            // given
            val opaqueId = "validOpaqueId"
            val nickname = "testUser"
            val email = "test@email.com"

            val mockMember = mock<MemberEntity>()
            val mockAuthProvider = mock<AuthProviderEntity>()

            whenever(mockMember.opaqueId).thenReturn(opaqueId)
            whenever(mockMember.nickname).thenReturn(nickname)
            whenever(mockAuthProvider.member).thenReturn(mockMember)
            whenever(mockAuthProvider.providerType).thenReturn(ProviderType.EMAIL)
            whenever(mockMember.primaryEmail).thenReturn(email)

            whenever(memberRepository.findByOpaqueId(opaqueId)).thenReturn(Optional.of(mockMember))
            whenever(authProviderRepository.findByMember(mockMember)).thenReturn(listOf(mockAuthProvider))

            // when
            val result = memberService.getUserInfo(opaqueId)

            // then
            result.nickname shouldBe nickname
            result.email shouldBe email

            verify(memberRepository).findByOpaqueId(opaqueId)
            verify(authProviderRepository).findByMember(mockMember)
        }

        it("GOOGLE 타입 provider만 있을 때 GOOGLE provider의 정보를 반환한다") {
            // given
            val opaqueId = "validOpaqueId"
            val nickname = "testUser"
            val googleEmail = "test@google.com"

            val mockMember = mock<MemberEntity>()
            val mockGoogleProvider = mock<AuthProviderEntity>()

            whenever(mockMember.opaqueId).thenReturn(opaqueId)
            whenever(mockMember.nickname).thenReturn(nickname)
            whenever(mockGoogleProvider.member).thenReturn(mockMember)
            whenever(mockGoogleProvider.providerType).thenReturn(ProviderType.GOOGLE)
            whenever(mockMember.primaryEmail).thenReturn(googleEmail)

            whenever(memberRepository.findByOpaqueId(opaqueId)).thenReturn(Optional.of(mockMember))
            whenever(authProviderRepository.findByMember(mockMember)).thenReturn(listOf(mockGoogleProvider))

            // when
            val result = memberService.getUserInfo(opaqueId)

            // then
            result.nickname shouldBe nickname
            result.email shouldBe googleEmail

            verify(memberRepository).findByOpaqueId(opaqueId)
            verify(authProviderRepository).findByMember(mockMember)
        }

        it("NAVER 타입 provider만 있을 때 NAVER provider의 정보를 반환한다") {
            // given
            val opaqueId = "validOpaqueId"
            val nickname = "testUser"
            val naverEmail = "test@naver.com"

            val mockMember = mock<MemberEntity>()
            val mockNaverProvider = mock<AuthProviderEntity>()

            whenever(mockMember.opaqueId).thenReturn(opaqueId)
            whenever(mockMember.nickname).thenReturn(nickname)
            whenever(mockNaverProvider.member).thenReturn(mockMember)
            whenever(mockNaverProvider.providerType).thenReturn(ProviderType.NAVER)
            whenever(mockMember.primaryEmail).thenReturn(naverEmail)

            whenever(memberRepository.findByOpaqueId(opaqueId)).thenReturn(Optional.of(mockMember))
            whenever(authProviderRepository.findByMember(mockMember)).thenReturn(listOf(mockNaverProvider))

            // when
            val result = memberService.getUserInfo(opaqueId)

            // then
            result.nickname shouldBe nickname
            result.email shouldBe naverEmail

            verify(memberRepository).findByOpaqueId(opaqueId)
            verify(authProviderRepository).findByMember(mockMember)
        }

        it("존재하지 않는 opaqueId가 주어지면 MemberException이 발생한다") {
            // given
            val invalidOpaqueId = "invalidOpaqueId"

            whenever(memberRepository.findByOpaqueId(invalidOpaqueId)).thenReturn(Optional.empty())

            // when & then
            val exception = shouldThrow<MemberException> {
                memberService.getUserInfo(invalidOpaqueId)
            }
            exception.code shouldBe MemberExceptionCode.USER_INFO_RETRIEVE_FAILED

            verify(memberRepository).findByOpaqueId(invalidOpaqueId)
        }

        it("member는 존재하지만 authProvider가 없으면 MemberException이 발생한다") {
            // given
            val opaqueId = "validOpaqueId"
            val nickname = "testUser"

            val mockMember = mock<MemberEntity>()
            whenever(mockMember.opaqueId).thenReturn(opaqueId)
            whenever(mockMember.nickname).thenReturn(nickname)

            whenever(memberRepository.findByOpaqueId(opaqueId)).thenReturn(Optional.of(mockMember))
            whenever(authProviderRepository.findByMember(mockMember)).thenReturn(emptyList())

            // when & then
            val exception = shouldThrow<MemberException> {
                memberService.getUserInfo(opaqueId)
            }
            exception.code shouldBe MemberExceptionCode.USER_INFO_RETRIEVE_FAILED

            verify(memberRepository).findByOpaqueId(opaqueId)
            verify(authProviderRepository).findByMember(mockMember)
        }
    }
})