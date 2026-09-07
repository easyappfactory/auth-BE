package com.wq.auth.integration

import com.wq.auth.api.domain.auth.AuthProviderRepository
import com.wq.auth.api.domain.auth.AuthService
import com.wq.auth.api.domain.auth.SocialLoginMemberProcessor
import com.wq.auth.api.domain.auth.entity.AuthProviderEntity
import com.wq.auth.api.domain.auth.entity.ProviderType
import com.wq.auth.api.domain.member.MemberRepository
import com.wq.auth.api.domain.member.entity.MemberEntity
import com.wq.auth.api.domain.oauth.OAuthUser
import io.kotest.core.spec.style.StringSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import java.time.LocalDateTime

/**
 * 로그인 시 last_login_at 이 실제 DB 에 커밋되는지 검증한다.
 *
 * 서비스 단위 테스트는 리포지토리를 mock 하므로 "메서드가 호출됐다"까지만 확인된다.
 * 과거 @Async 별도 트랜잭션 갱신이 미커밋 행을 못 보거나 뒤늦은 flush 에 덮여
 * 값이 사라진 회귀가 있어, 여기서는 실제 DB 로 커밋 결과를 본다.
 */
@SpringBootTest(
    properties = [
        "jwt.secret=MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
        "jwt.access-exp=15m",
        "jwt.refresh-exp=14d",
        "INTERNAL_API_SECRET=test-internal-secret",
        "INTERNAL_LOGGING_SECRET=test-logging-secret",
        "SECURITY_ALERT_CHAT_WEBHOOK_URL=",
        "spring.datasource.url=jdbc:h2:mem:last-login-test;DB_CLOSE_DELAY=-1",
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
class LastLoginAtUpdateTest : StringSpec() {

    override val extensions = listOf(SpringExtension())

    @Autowired lateinit var authService: AuthService
    @Autowired lateinit var socialLoginMemberProcessor: SocialLoginMemberProcessor
    @Autowired lateinit var memberRepository: MemberRepository
    @Autowired lateinit var authProviderRepository: AuthProviderRepository

    /** DB 에서 다시 읽는다. 갱신은 로그인 트랜잭션 안에서 끝나므로 대기가 필요 없다. */
    private fun lastLoginAtOf(memberId: Long): LocalDateTime? =
        memberRepository.findById(memberId).orElseThrow().lastLoginAt

    init {
        "기존 이메일 회원 로그인 → last_login_at 기록" {
            val email = "email-login@test.com"
            val member = memberRepository.save(MemberEntity.create(nickname = "이메일회원"))
            authProviderRepository.save(AuthProviderEntity.createEmailProvider(member, email))
            member.lastLoginAt shouldBe null

            val before = LocalDateTime.now()
            authService.emailLogin(email, deviceId = "dev-1")

            lastLoginAtOf(member.id).shouldNotBeNull().isAfter(before) shouldBe true
        }

        "기존 소셜 회원 로그인(전화번호 변경 없음) → last_login_at 기록" {
            val member = memberRepository.save(MemberEntity.create(nickname = "소셜회원"))
            authProviderRepository.save(
                AuthProviderEntity(member = member, providerType = ProviderType.KAKAO, providerId = "kakao-1", email = "k1@test.com")
            )

            val before = LocalDateTime.now()
            socialLoginMemberProcessor.processMemberAndIssueTokens(
                OAuthUser(providerId = "kakao-1", email = "k1@test.com", verifiedEmail = true, name = "소셜회원", providerType = ProviderType.KAKAO),
                ProviderType.KAKAO,
            )

            lastLoginAtOf(member.id).shouldNotBeNull().isAfter(before) shouldBe true
        }

        "기존 소셜 회원 로그인(전화번호 변경) → last_login_at 기록" {
            val member = memberRepository.save(MemberEntity.create(nickname = "소셜회원2"))
            authProviderRepository.save(
                AuthProviderEntity(member = member, providerType = ProviderType.NAVER, providerId = "naver-1", email = "n1@test.com")
            )

            val before = LocalDateTime.now()
            socialLoginMemberProcessor.processMemberAndIssueTokens(
                OAuthUser(providerId = "naver-1", email = "n1@test.com", verifiedEmail = true, name = "소셜회원2", phoneNumber = "010-1234-5678", providerType = ProviderType.NAVER),
                ProviderType.NAVER,
            )

            lastLoginAtOf(member.id).shouldNotBeNull().isAfter(before) shouldBe true
            memberRepository.findById(member.id).orElseThrow().phoneNumber shouldBe "010-1234-5678"
        }

        "신규 소셜 회원 가입 로그인 → last_login_at 기록" {
            val before = LocalDateTime.now()
            socialLoginMemberProcessor.processMemberAndIssueTokens(
                OAuthUser(providerId = "google-new", email = "new@test.com", verifiedEmail = true, name = "신규소셜", providerType = ProviderType.GOOGLE),
                ProviderType.GOOGLE,
            )
            val member = authProviderRepository.findByProviderIdAndProviderType("google-new", ProviderType.GOOGLE)!!.member

            lastLoginAtOf(member.id).shouldNotBeNull().isAfter(before) shouldBe true
        }

        "토큰 재발급은 last_login_at 을 갱신하지 않는다" {
            val email = "refresh-no-touch@test.com"
            val member = memberRepository.save(MemberEntity.create(nickname = "재발급회원"))
            authProviderRepository.save(AuthProviderEntity.createEmailProvider(member, email))

            val loginResult = authService.emailLogin(email, deviceId = "dev-1")
            val afterLogin = lastLoginAtOf(member.id).shouldNotBeNull()

            authService.refreshAccessToken(loginResult.refreshToken, deviceId = "dev-1")

            lastLoginAtOf(member.id) shouldBe afterLogin
        }
    }
}
