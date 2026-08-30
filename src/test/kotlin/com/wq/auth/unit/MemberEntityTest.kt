package com.wq.auth.unit

import com.wq.auth.api.domain.member.entity.MemberEntity
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.time.Instant
import java.util.*

class MemberEntityTest : StringSpec({

    "MemberEntity.create()를 통해 정상적으로 생성된다" {
        // Given & When
        val member = MemberEntity.create(
            nickname = "테스트사용자"
        )

        // Then
        member.nickname shouldBe "테스트사용자"
        member.opaqueId shouldNotBe null
        UUID.fromString(member.opaqueId) // UUID 형식 검증
        member.isEmailVerified shouldBe false
        member.isDeleted shouldBe false
    }

    "닉네임이 공백이면 예외가 발생한다" {
        // Given & When & Then
        shouldThrow<IllegalArgumentException> {
            MemberEntity.create(nickname = "")
        }.message shouldBe "닉네임은 필수입니다"
    }

    "닉네임이 100자를 초과하면 예외가 발생한다" {
        // Given
        val longNickname = "a".repeat(101)

        // When & Then
        shouldThrow<IllegalArgumentException> {
            MemberEntity.create(nickname = longNickname)
        }.message shouldBe "닉네임은 100자를 초과할 수 없습니다"
    }

    "닉네임 앞뒤 공백이 자동으로 제거된다" {
        // Given & When
        val member = MemberEntity.create(nickname = "  테스트  ")

        // Then
        member.nickname shouldBe "테스트"
    }

    "이메일 인증 처리가 정상 작동한다" {
        // Given
        val member = MemberEntity.create(nickname = "테스트")

        // When
        member.verifyEmail()

        // Then
        member.isEmailVerified shouldBe true
    }

    "전화번호 업데이트가 정상 작동한다" {
        // Given
        val member = MemberEntity.createSocialMember(
            nickname = "테스트",
            primaryEmail = "test@naver.com",
            phoneNumber = "01011112222"
        )

        // When
        member.updatePhoneNumber("01012345678")

        // Then
        member.phoneNumber shouldBe "01012345678"
    }

    "createSocialMember는 phoneNumber 없이도 생성된다" {
        // Given & When
        val member = MemberEntity.createSocialMember(
            nickname = "테스트",
            primaryEmail = "test@naver.com"
        )

        // Then
        member.phoneNumber shouldBe null
    }

    /*
    // 다음 코드는 컴파일 에러가 발생해야 함 (protected constructor)
    "외부에서 직접 생성자 호출 시도" {
        // 이 코드는 컴파일되지 않아야 함
        // val member = MemberEntity(
        //     opaqueId = "test-uuid",
        //     nickname = "테스트"
        // )
    }
    */

    "새로 만든 회원은 폐기 이력이 없다" {
        val member = MemberEntity.create(nickname = "테스터")

        member.tokensInvalidBefore shouldBe null
    }

    "revokeTokens()는 전달한 시각을 폐기 기준으로 기록한다" {
        // Given
        val member = MemberEntity.create(nickname = "테스터")
        val at = Instant.parse("2026-08-30T12:00:00Z")

        // When
        member.revokeTokens(at)

        // Then
        member.tokensInvalidBefore shouldBe at
    }

    "revokeTokens()를 인자 없이 부르면 현재 시각으로 기록한다" {
        // Given
        val member = MemberEntity.create(nickname = "테스터")
        val before = Instant.now().minusSeconds(1)

        // When
        member.revokeTokens()

        // Then
        val recorded = member.tokensInvalidBefore
        recorded shouldNotBe null
        recorded!!.isAfter(before) shouldBe true
    }
})

