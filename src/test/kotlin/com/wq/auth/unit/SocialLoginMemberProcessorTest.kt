package com.wq.auth.unit

import com.wq.auth.api.domain.auth.AuthProviderRepository
import com.wq.auth.api.domain.auth.RefreshTokenRepository
import com.wq.auth.api.domain.auth.SocialLoginMemberProcessor
import com.wq.auth.api.domain.auth.entity.AuthProviderEntity
import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.member.MemberRepository
import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.domain.oauth.OAuthUser
import com.wq.auth.security.jwt.JwtProvider
import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import org.mockito.kotlin.*

class SocialLoginMemberProcessorTest : DescribeSpec({

    lateinit var authProviderRepository: AuthProviderRepository
    lateinit var memberRepository: MemberRepository
    lateinit var jwtProvider: JwtProvider
    lateinit var refreshTokenRepository: RefreshTokenRepository
    lateinit var processor: SocialLoginMemberProcessor

    fun naverOAuthUser(phoneNumber: String?) = OAuthUser(
        providerId = "naver-provider-id",
        email = "test@naver.com",
        verifiedEmail = true,
        name = "테스트",
        givenName = null,
        phoneNumber = phoneNumber,
        providerType = ProviderType.NAVER
    )

    beforeEach {
        authProviderRepository = mock()
        memberRepository = mock()
        jwtProvider = mock()
        refreshTokenRepository = mock()
        processor = SocialLoginMemberProcessor(
            authProviderRepository,
            memberRepository,
            jwtProvider,
            refreshTokenRepository,
        )

        whenever(jwtProvider.createAccessToken(any(), any())).thenReturn("access-token")
        whenever(jwtProvider.createRefreshToken(any(), any())).thenReturn("refresh-token")
        whenever(jwtProvider.getJti(any())).thenReturn("jti")
        whenever(jwtProvider.getOpaqueId(any())).thenReturn("opaque-id")
        whenever(memberRepository.save(any<MemberEntity>())).thenAnswer { it.arguments[0] }
    }

    describe("전화번호 저장 및 갱신") {

        it("신규 회원 가입 시 phoneNumber가 저장된다") {
            // given
            whenever(authProviderRepository.findByProviderIdAndProviderType(any(), any())).thenReturn(null)
            whenever(authProviderRepository.findByMemberAndProviderType(any(), any())).thenReturn(null)
            whenever(authProviderRepository.save(any<AuthProviderEntity>())).thenAnswer { it.arguments[0] }

            // when
            processor.processMemberAndIssueTokens(naverOAuthUser("01012345678"), ProviderType.NAVER)

            // then
            val captor = argumentCaptor<MemberEntity>()
            verify(memberRepository).save(captor.capture())
            captor.firstValue.phoneNumber shouldBe "01012345678"
        }

        it("기존 회원 재로그인 시 phoneNumber가 항상 최신 값으로 갱신된다") {
            // given
            val existingMember = MemberEntity.createSocialMember(
                nickname = "테스트",
                primaryEmail = "test@naver.com",
                phoneNumber = "01011112222"
            )
            val before = existingMember.lastLoginAt
            Thread.sleep(2)
            val existingAuthProvider = mock<AuthProviderEntity>()
            whenever(existingAuthProvider.member).thenReturn(existingMember)
            whenever(authProviderRepository.findByProviderIdAndProviderType(any(), any()))
                .thenReturn(existingAuthProvider)
            whenever(authProviderRepository.findByMemberAndProviderType(any(), any()))
                .thenReturn(existingAuthProvider)

            // when
            processor.processMemberAndIssueTokens(naverOAuthUser("01099998888"), ProviderType.NAVER)

            // then
            existingMember.phoneNumber shouldBe "01099998888"
            existingMember.lastLoginAt shouldNotBe before
            verify(memberRepository).save(existingMember)
        }

        it("소셜 응답에 phoneNumber가 없으면 기존 값이 유지된다") {
            // given
            val existingMember = MemberEntity.createSocialMember(
                nickname = "테스트",
                primaryEmail = "test@naver.com",
                phoneNumber = "01011112222"
            )
            val existingAuthProvider = mock<AuthProviderEntity>()
            whenever(existingAuthProvider.member).thenReturn(existingMember)
            whenever(authProviderRepository.findByProviderIdAndProviderType(any(), any()))
                .thenReturn(existingAuthProvider)
            whenever(authProviderRepository.findByMemberAndProviderType(any(), any()))
                .thenReturn(existingAuthProvider)

            // when
            processor.processMemberAndIssueTokens(naverOAuthUser(null), ProviderType.NAVER)

            // then
            existingMember.phoneNumber shouldBe "01011112222"
            verify(memberRepository, never()).save(any<MemberEntity>())
        }
    }
})
