package com.wq.auth.integration.security

import com.wq.auth.security.jwt.JwtProvider
import io.kotest.core.spec.style.BehaviorSpec
import io.kotest.extensions.spring.SpringExtension
import io.kotest.matchers.shouldBe
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get

/**
 * JWT 기반 Spring Security 통합 테스트
 *
 * 테스트 시나리오:
 * 1. 공개 API - 토큰 없이 접근 가능
 * 2. 인증 API - 유효한 토큰 필요
 * 3. JWT 토큰 형식 검증 (Bearer, 만료, 잘못된 형식)
 * 4. 권한별 접근 제어 (401 응답)
 *
 * 참고: Role/Admin 기능은 현재 API에서 제거되어 관련 케이스는 제외됨
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = [
        "INTERNAL_API_SECRET=test-internal-secret",
        "spring.datasource.url=jdbc:h2:mem:security-test;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "jwt.secret=MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
        "jwt.access-exp=15m",
        "jwt.refresh-exp=14d",
        "spring.mail.host=localhost",
        "spring.mail.port=25",
        "spring.mail.username=test",
        "spring.mail.password=test",
        "spring.mail.properties.mail.smtp.auth=false",
        "spring.mail.properties.mail.smtp.starttls.enable=false"
    ]
)
@AutoConfigureMockMvc
class JwtSpringSecurityIntegrationTest : BehaviorSpec() {

    override val extensions = listOf(SpringExtension())

    @Autowired
    lateinit var mockMvc: MockMvc

    @Autowired
    lateinit var jwtProvider: JwtProvider

    init {
        given("JWT 기반 Spring Security 시스템에서") {

            `when`("공개 API에 토큰 없이 접근하면") {
                then("200 OK 응답을 받아야 한다") {
                    val result = mockMvc.perform(
                        get("/api/public/test")
                            .contentType(MediaType.APPLICATION_JSON)
                    ).andReturn()

                    result.response.status shouldBe 200
                }
            }

            `when`("인증된 사용자 API에 유효한 토큰으로 접근하면") {
                then("200 OK 응답을 받아야 한다") {
                    // Given: 토큰 생성
                    val memberToken = jwtProvider.createAccessToken(
                        opaqueId = "550e8400-e29b-41d4-a716-446655440000"
                    )

                    val result = mockMvc.perform(
                        get("/api/test")
                            .header("Authorization", "Bearer $memberToken")
                            .contentType(MediaType.APPLICATION_JSON)
                    ).andReturn()

                    result.response.status shouldBe 200
                }
            }

            `when`("인증된 사용자 API에 토큰 없이 접근하면") {
                then("401 Unauthorized 응답을 받아야 한다") {
                    val result = mockMvc.perform(
                        get("/api/authenticated/test")
                            .contentType(MediaType.APPLICATION_JSON)
                    ).andReturn()

                    result.response.status shouldBe 401
                }
            }

            `when`("잘못된 JWT 토큰으로 접근하면") {
                then("401 Unauthorized 응답을 받아야 한다") {
                    val result = mockMvc.perform(
                        get("/api/authenticated/test")
                            .header("Authorization", "Bearer invalid.token.here")
                            .contentType(MediaType.APPLICATION_JSON)
                    ).andReturn()

                    result.response.status shouldBe 401
                }
            }

            `when`("Bearer 없는 토큰으로 접근하면") {
                then("401 Unauthorized 응답을 받아야 한다") {
                    val memberToken = jwtProvider.createAccessToken(
                        opaqueId = "550e8400-e29b-41d4-a716-446655440000"
                    )

                    val result = mockMvc.perform(
                        get("/api/authenticated/test")
                            .header("Authorization", memberToken) // Bearer 없이
                            .contentType(MediaType.APPLICATION_JSON)
                    ).andReturn()

                    result.response.status shouldBe 401
                }
            }

            `when`("만료된 JWT 토큰으로 접근하면") {
                then("401 Unauthorized 응답을 받아야 한다") {
                    // Given: 만료된 토큰 (과거 시간으로 설정)
                    val expiredToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJpYXQiOjE2MDAwMDAwMDAsImV4cCI6MTYwMDAwMDAwMX0.invalid"

                    val result = mockMvc.perform(
                        get("/api/authenticated/test")
                            .header("Authorization", "Bearer $expiredToken")
                            .contentType(MediaType.APPLICATION_JSON)
                    ).andReturn()

                    result.response.status shouldBe 401
                }
            }
        }
    }
}
