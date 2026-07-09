package com.wq.auth.unit

import com.wq.auth.security.jwt.JwtProperties
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.context.properties.ConfigurationPropertiesScan
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.TestPropertySource
import java.time.Duration

/**
 * JwtProperties 바인딩 테스트
 * Kotest-extensions-spring 이 Kotest 6.x 를 지원하지 않으므로
 * JUnit 5 기반 Spring 테스트로 작성합니다.
 */
@SpringBootTest(
    properties = [
        "spring.datasource.url=jdbc:h2:mem:jwt-props-test;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
        "INTERNAL_API_SECRET=test-internal-secret"
    ]
)
@ConfigurationPropertiesScan
@TestPropertySource(properties = [
    // 32바이트(256bit) Base64 시크릿 예시
    "jwt.secret=MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE===",
    "jwt.access-exp=15m",
    "jwt.refresh-exp=14d"
])
class JwtPropertiesBindingTest {

    @Autowired
    lateinit var props: JwtProperties

    @Test
    fun `JwtProperties 가 yml 값으로 정상 바인딩된다`() {
        assertThat(props.secret).isEqualTo("MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE===")
        assertThat(props.accessExp).isEqualTo(Duration.ofMinutes(15))
        assertThat(props.refreshExp).isEqualTo(Duration.ofDays(14))
    }
}
