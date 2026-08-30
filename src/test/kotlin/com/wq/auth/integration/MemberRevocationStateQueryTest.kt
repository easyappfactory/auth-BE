package com.wq.auth.integration

import com.wq.auth.api.domain.member.MemberRepository
import com.wq.auth.api.domain.member.entity.MemberEntity
import io.kotest.core.spec.style.StringSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import java.time.Instant

/**
 * 폐기 판정 쿼리의 **프로젝션 바인딩**을 실제 DB로 검증한다.
 *
 * 서비스 단위 테스트는 리포지토리를 mock 하므로, 프로젝션 별칭이 잘못돼도 통과한다.
 * 이 판정은 인증의 핵심이라 "쿼리가 실제로 값을 채워 오는가"를 별도로 확인한다.
 */
@SpringBootTest(
    properties = [
        "jwt.secret=MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
        "jwt.access-exp=15m",
        "jwt.refresh-exp=14d",
        "INTERNAL_API_SECRET=test-internal-secret",
        "INTERNAL_LOGGING_SECRET=test-logging-secret",
        "SECURITY_ALERT_CHAT_WEBHOOK_URL=",
        "spring.datasource.url=jdbc:h2:mem:revocation-state-test;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "spring.mail.host=localhost",
        "spring.mail.port=25",
        "spring.mail.username=test",
        "spring.mail.password=test",
        "spring.mail.properties.mail.smtp.auth=false",
        "spring.mail.properties.mail.smtp.starttls.enable=false",
    ]
)
class MemberRevocationStateQueryTest : StringSpec() {

    override val extensions = listOf(SpringExtension())

    @Autowired
    lateinit var memberRepository: MemberRepository

    init {
        "회원이 없으면 null 을 돌려준다 — 탈퇴(hard delete)를 이 값으로 판정한다" {
            memberRepository.findRevocationStateByOpaqueId("존재하지-않는-id") shouldBe null
        }

        "폐기 이력이 없는 정상 회원은 isDeleted=false, tokensInvalidBefore=null" {
            val member = memberRepository.save(MemberEntity.create(nickname = "정상회원"))

            val state = memberRepository.findRevocationStateByOpaqueId(member.opaqueId)

            state.shouldNotBeNull()
            state.isDeleted shouldBe false
            state.tokensInvalidBefore shouldBe null
        }

        "revokeTokens() 로 기록한 시각이 그대로 조회된다" {
            val at = Instant.parse("2026-08-30T12:00:00Z")
            val member = MemberEntity.create(nickname = "로그아웃회원").apply { revokeTokens(at) }
            memberRepository.save(member)

            val state = memberRepository.findRevocationStateByOpaqueId(member.opaqueId)

            state.shouldNotBeNull()
            state.tokensInvalidBefore shouldBe at
        }

        "soft delete 된 회원은 행이 남지만 isDeleted=true 로 조회된다" {
            // 계정 병합(MemberConnector)이 흡수된 회원을 이렇게 처리한다.
            // 행이 남으므로 null 로는 구분할 수 없고, 이 플래그로만 알 수 있다.
            val member = MemberEntity.create(nickname = "병합된회원").apply { softDelete() }
            memberRepository.save(member)

            val state = memberRepository.findRevocationStateByOpaqueId(member.opaqueId)

            state.shouldNotBeNull()
            state.isDeleted shouldBe true
        }
    }
}
