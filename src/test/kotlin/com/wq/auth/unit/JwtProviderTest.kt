package com.wq.auth.unit

import com.wq.auth.security.jwt.JwtProperties
import com.wq.auth.security.jwt.JwtProvider
import com.wq.auth.security.jwt.error.JwtException
import com.wq.auth.security.jwt.error.JwtExceptionCode
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.security.Keys
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.time.Duration
import java.util.Base64
import javax.crypto.SecretKey

class JwtProviderTest : StringSpec({

    // 256-bit(32byte) 시크릿을 Base64로 준비
    val plain = "01234567890123456789012345678901" // 32 chars = 256-bit (ASCII)
    val secretB64 = Base64.getEncoder().encodeToString(plain.toByteArray())

    val props = JwtProperties(
        secret = secretB64,
        accessExp = Duration.ofMinutes(5),   // 테스트 실행에 충분한 시간
        refreshExp = Duration.ofDays(14)
    )
    val provider = JwtProvider(props)

    "간소화된 AccessToken을 발급하면 opaqueId 파싱이 정상 동작한다" {
        val opaqueId = "550e8400-e29b-41d4-a716-446655440000"
        val token = provider.createAccessToken(opaqueId)
        provider.getOpaqueId(token) shouldBe opaqueId
    }

    "AccessToken에 extraClaims가 실제로 들어간다" {
        val opaqueId = "550e8400-e29b-41d4-a716-446655440000"
        val token = provider.createAccessToken(opaqueId, mapOf("role" to "ADMIN"))

        val key: SecretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(props.secret))
        val claims = Jwts.parser().verifyWith(key).build().parseSignedClaims(token).payload
        claims["role"] shouldBe "ADMIN"
        claims.subject shouldBe opaqueId
    }

    "위조된 토큰은 JwtException(INVALID_SIGNATURE)을 던진다" {
        fun b64(s: String) = Base64.getEncoder().encodeToString(s.toByteArray())
        val keyB = b64("abcdefghijklmnopqrstuvwxyzABCDEF") // 다른 키(32바이트)
        val providerWithAnotherKey = JwtProvider(
            JwtProperties(secret = keyB, accessExp = Duration.ofMinutes(5), refreshExp = Duration.ofDays(14))
        )
        val tokenSignedByB = providerWithAnotherKey.createAccessToken("550e8400-e29b-41d4-a716-446655440000")

        val ex = shouldThrow<JwtException> {
            provider.validateOrThrow(tokenSignedByB)
        }
        ex.jwtCode shouldBe JwtExceptionCode.INVALID_SIGNATURE
    }

    "만료된 토큰은 JwtException(EXPIRED)을 던진다" {
        // 별도의 짧은 만료 시간을 가진 provider 생성
        val shortExpProps = JwtProperties(
            secret = secretB64,
            accessExp = Duration.ofMillis(100), // 100ms로 매우 짧게
            refreshExp = Duration.ofDays(14)
        )
        val shortExpProvider = JwtProvider(shortExpProps)
        
        val token = shortExpProvider.createAccessToken("550e8400-e29b-41d4-a716-446655440000")
        Thread.sleep(200) // 100ms 대기
        val ex = shouldThrow<JwtException> { shortExpProvider.validateOrThrow(token) }
        ex.jwtCode shouldBe JwtExceptionCode.EXPIRED
    }

    "RefreshToken을 발급하면 opaqueId 파싱이 정상 동작한다" {
        val opaqueId = "550e8400-e29b-41d4-a716-446655440000"
        val rt = provider.createRefreshToken(opaqueId)
        provider.getOpaqueId(rt) shouldBe opaqueId
    }

    "RefreshToken에는 jti가 포함된다" {
        val opaqueId = "550e8400-e29b-41d4-a716-446655440000"
        val rt = provider.createRefreshToken(opaqueId)
        val key: SecretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(props.secret))
        val claims = Jwts.parser().verifyWith(key).build().parseSignedClaims(rt).payload
        (claims.id?.isNotBlank() ?: false).shouldBeTrue()
    }

    "세그먼트가 2개면 MALFORMED를 던진다" {
        val malformed = "abc.def" // 3개가 아닌 compact JWS
        val ex = shouldThrow<JwtException> { provider.validateOrThrow(malformed) }
        ex.jwtCode shouldBe JwtExceptionCode.MALFORMED
    }

    "alg=none 토큰은 UNSUPPORTED를 던진다" {
        val headerJson = """{"alg":"none","typ":"JWT"}"""
        val payloadJson = """{"sub":"user-123"}"""
        val headerB64 = Encoders.BASE64URL.encode(headerJson.toByteArray())
        val payloadB64 = Encoders.BASE64URL.encode(payloadJson.toByteArray())
        val signatureB64 = Encoders.BASE64URL.encode("sig".toByteArray())

        val unsupported = "$headerB64.$payloadB64.$signatureB64"

        val ex = shouldThrow<JwtException> { provider.validateOrThrow(unsupported) }
        ex.jwtCode shouldBe JwtExceptionCode.UNSUPPORTED
    }

    "빈 토큰 문자열이면 TOKEN_MISSING을 던진다" {
        val ex = shouldThrow<JwtException> { provider.validateOrThrow("") }
        ex.jwtCode shouldBe JwtExceptionCode.TOKEN_MISSING
    }

    "토큰 생성 시 올바른 구조와 클레임이 포함된다" {
        val opaqueId = "550e8400-e29b-41d4-a716-446655440000"
        val roleName = "ADMIN"
        val token = provider.createAccessToken(opaqueId, mapOf("role" to roleName))
        
        // 토큰 구조 검증 (3개 세그먼트)
        val segments = token.split(".")
        segments.size shouldBe 3
        
        // 실제 클레임 구조 확인
        val key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(props.secret))
        val claims = Jwts.parser().verifyWith(key).build().parseSignedClaims(token).payload
        
        claims.subject shouldBe opaqueId
        claims["role"] shouldBe roleName
        claims.issuedAt shouldNotBe null
        claims.expiration shouldNotBe null
    }

    "토큰 유효성 검증이 정상 동작한다" {
        val validToken = provider.createAccessToken("test-user")
        
        // 예외 없이 통과해야 함
        provider.validateOrThrow(validToken)
    }
})