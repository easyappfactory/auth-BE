package com.wq.auth.security.jwt

import com.wq.auth.security.jwt.error.JwtException
import com.wq.auth.security.jwt.error.JwtExceptionCode
import com.github.f4b6a3.uuid.UuidCreator
import io.jsonwebtoken.Claims
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.UnsupportedJwtException
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.SignatureException
import org.springframework.stereotype.Component
import java.time.Instant
import java.util.*
import javax.crypto.SecretKey

@Component
class JwtProvider(
    private val jwtProperties: JwtProperties
) {
    private val key: SecretKey = Keys.hmacShaKeyFor(
        Decoders.BASE64.decode(jwtProperties.secret)
    )

    fun createAccessToken(
        opaqueId: String,
        extraClaims: Map<String, Any?> = emptyMap()
    ): String {
        val now = Instant.now()
        val exp = Date.from(now.plus(jwtProperties.accessExp))

        return Jwts.builder()
            .subject(opaqueId)
            .issuedAt(Date.from(now))
            .expiration(exp)
            .apply {
                extraClaims.forEach { (key, value) ->
                    claim(key, value)
                }
            }
            .signWith(key, Jwts.SIG.HS256)
            .compact()
    }

    fun createRefreshToken(
        opaqueId: String,
        jti: String = UuidCreator.getTimeOrdered().toString()
    ): String {
        val now = Instant.now()
        val exp = Date.from(now.plus(jwtProperties.refreshExp))

        return Jwts.builder()
            .subject(opaqueId)
            .id(jti)                 // jti 클레임: RefreshToken 고유 식별자
            .issuedAt(Date.from(now))
            .expiration(exp)
            .signWith(key, Jwts.SIG.HS256)
            .compact()
    }

    /**
     * JWT 토큰에서 opaqueId(subject)를 추출합니다.
     * @param token 대상 JWT 토큰
     * @return 사용자의 opaqueId (UUID)
     */
    fun getOpaqueId(token: String): String =
        Jwts.parser().verifyWith(key)
            .build().parseSignedClaims(token)
            .payload
            .subject

    /**
     * JWT 토큰에서 jti(ID)를 추출합니다.
     * @param token 대상 JWT 토큰
     * @return JWT ID (RefreshToken 고유 식별자)
     */
    fun getJti(token: String): String =
        Jwts.parser().verifyWith(key)
            .build().parseSignedClaims(token)
            .payload
            .id

    /**
     * JWT 토큰에서 모든 클레임을 추출합니다.
     * @param token 대상 JWT 토큰
     * @return 모든 클레임을 담은 Map
     */
    fun getAllClaims(token: String): Map<String, Any> =
        Jwts.parser().verifyWith(key)
            .build().parseSignedClaims(token)
            .payload

    /**
     * 액세스 토큰의 만료 시간(초)을 반환합니다.
     * @return 액세스 토큰 만료 시간 (초 단위)
     */
    fun getAccessTokenExpirationSeconds(): Long = jwtProperties.accessExp.toSeconds()

    /**
     * RefreshToken의 만료 시각을 반환합니다.
     */
    fun getRefreshTokenExpiredAt(token: String): Instant =
        Jwts.parser().verifyWith(key)
            .build().parseSignedClaims(token)
            .payload
            .expiration.toInstant()

    /**
     * 토큰의 남은 유효 시간을 초 단위로 반환합니다.
     *
     * - 양수: 아직 유효하며 해당 초만큼 남음
     * - 음수(-1): 이미 만료된 토큰 (서명 자체는 유효)
     * - 서명 오류, 위조 등 구조적으로 유효하지 않은 토큰은 [JwtException] 을 던집니다.
     */
    fun getRemainingTimeSeconds(token: String): Long {
        return try {
            val expiration = Jwts.parser().verifyWith(key).build().parseSignedClaims(token).payload.expiration
            (expiration.time - System.currentTimeMillis()) / 1000
        } catch (e: ExpiredJwtException) {
            -1L
        } catch (t: Throwable) {
            throw JwtException(mapToCode(t), t)
        }
    }

    /**
     * 만료 여부와 관계없이 토큰의 클레임을 추출합니다.
     *
     * 만료된 토큰이라도 서명이 유효하다면 클레임을 반환합니다.
     * 이는 사일런트 리프레시 시 만료된 AT에서 opaqueId/deviceId를 읽어야 할 때 사용합니다.
     * 서명이 위조되거나 형식이 잘못된 경우에는 [JwtException] 을 던집니다.
     */
    fun getClaimsEvenIfExpired(token: String): Claims {
        return try {
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token).payload
        } catch (e: ExpiredJwtException) {
            e.claims
        } catch (t: Throwable) {
            throw JwtException(mapToCode(t), t)
        }
    }

    /**
     * 유효성 검사(예외 던짐) – 표준 에러로 변환
     * 컨트롤러/서비스에서 이 메서드를 사용하면 GlobalExceptionHandler가 잡아줍니다.
     */
    fun validateOrThrow(token: String) {
        try {
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token)
        } catch (throwable: Throwable) {
            throw JwtException(mapToCode(throwable), throwable)
        }
    }

    private fun mapToCode(throwable: Throwable): JwtExceptionCode = when (throwable) {
        is SignatureException,
        is SecurityException                -> JwtExceptionCode.INVALID_SIGNATURE
        is MalformedJwtException            -> JwtExceptionCode.MALFORMED
        is ExpiredJwtException              -> JwtExceptionCode.EXPIRED
        is UnsupportedJwtException          -> JwtExceptionCode.UNSUPPORTED
        is IllegalArgumentException         -> JwtExceptionCode.TOKEN_MISSING
        else                                -> JwtExceptionCode.MALFORMED
    }
}