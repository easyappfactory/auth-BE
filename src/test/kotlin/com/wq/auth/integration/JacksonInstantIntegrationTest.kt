package com.wq.auth.integration

import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import com.wq.auth.integration._tnote._TNote
import com.wq.auth.integration._tnote._TNoteRepository
import com.wq.auth.security.jwt.JwtProvider
import com.wq.auth.security.principal.PrincipalDetails
import com.wq.auth.shared.rateLimiter.RateLimiterInterceptor
import io.kotest.core.spec.style.StringSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import org.mockito.kotlin.any
import org.mockito.kotlin.doNothing
import org.mockito.kotlin.whenever
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user
import org.springframework.test.context.bean.override.mockito.MockitoBean
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneOffset

@SpringBootTest(
    properties = [
        "jwt.secret=MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
        "jwt.access-exp=15m",
        "jwt.refresh-exp=14d",
        "INTERNAL_API_SECRET=test-internal-secret",
        "INTERNAL_LOGGING_SECRET=test-logging-secret",
        "SECURITY_ALERT_CHAT_WEBHOOK_URL=",
        "spring.datasource.url=jdbc:h2:mem:jackson-instant-test;DB_CLOSE_DELAY=-1",
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
        "spring.mail.properties.mail.smtp.starttls.enable=false"
    ]
)
@AutoConfigureMockMvc
class JacksonInstantIntegrationTest : StringSpec() {

    override val extensions = listOf(SpringExtension())

    @Autowired
    lateinit var repo: _TNoteRepository

    @Autowired
    lateinit var mockMvc: MockMvc

    @Autowired
    lateinit var objectMapper: JsonMapper

    @MockitoBean
    lateinit var jwtProvider: JwtProvider

    @MockitoBean
    lateinit var rateLimiterInterceptor: RateLimiterInterceptor

    init {
        beforeTest {
            whenever(rateLimiterInterceptor.preHandle(any(), any(), any())).thenReturn(true)
            doNothing().whenever(jwtProvider).validateOrThrow(any())
            whenever(jwtProvider.getOpaqueId(any())).thenReturn("opaqueId")
        }

        "UTC Instant가 저장/조회 시 동일하다" {
            // given
            val utc = Instant.parse("2025-08-12T00:00:00Z")
            val saved = repo.save(_TNote(title = "hello", publishedAt = utc))

            // when
            val found = repo.findById(saved.id!!).orElseThrow()

            // then
            found.publishedAt shouldBe utc
        }

        "응답 JSON은 +09:00 및 :ss로 나가고 시점은 동일하다" {
            // given
            val utc = Instant.parse("2025-08-12T00:00:00Z")
            val saved = repo.save(_TNote(title = "hello", publishedAt = utc))
            val accessToken = "valid-access-token"

            val principal = PrincipalDetails(
                opaqueId = "opaqueId"
            )

            // when
            val res = mockMvc.get("/test-notes/{id}", saved.id!!) {
                accept = MediaType.APPLICATION_JSON
                header("Authorization", "Bearer $accessToken")
                with(user(principal))
            }.andReturn().response
            res.status shouldBe 200

            // then: 포맷 문자열 검증 (+09:00 & :ss)
            val body = res.contentAsString
            body shouldContain "\"publishedAt\":\"2025-08-12T09:00:00+09:00\""

            // 의미 검증: 파싱하여 오프셋/Instant 동일성 확인
            val node: JsonNode = objectMapper.readTree(body)
            val iso = node["publishedAt"]?.asText()
                ?: error("publishedAt 필드가 없음.")
            val parsed = OffsetDateTime.parse(iso)

            parsed.offset shouldBe ZoneOffset.ofHours(9)  // 응답은 +09:00
            parsed.toInstant() shouldBe utc               // 시점은 동일(UTC)
        }
    }
}
