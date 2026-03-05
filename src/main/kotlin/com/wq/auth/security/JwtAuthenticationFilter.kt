package com.wq.auth.security

import com.wq.auth.security.jwt.JwtProvider
import com.wq.auth.security.jwt.error.JwtException
import com.wq.auth.security.principal.PrincipalDetails
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import io.github.oshai.kotlinlogging.KotlinLogging

@Component
class JwtAuthenticationFilter(
    private val jwtProvider: JwtProvider
) : OncePerRequestFilter() {

    private val log = KotlinLogging.logger {}

    companion object {
        private const val AUTHORIZATION_HEADER = "Authorization"
        private const val BEARER_PREFIX = "Bearer "

        /**
         * HTTP 요청에서 JWT 토큰을 추출합니다.
         *
         * 토큰 우선순위:
         * 1. `accessToken` HttpOnly 쿠키 (웹 클라이언트 전용)
         *    - 쿠키가 존재하면 헤더는 완전히 무시됩니다.
         * 2. `Authorization: Bearer <token>` 헤더 (앱 클라이언트 / 쿠키 없을 때만 사용)
         *
         * @return 토큰 문자열, 아무것도 없으면 null
         */
        fun extractToken(request: HttpServletRequest): String? {
            val accessTokenCookie = request.cookies?.firstOrNull { it.name == "accessToken" }

            if (accessTokenCookie != null) {
                return accessTokenCookie.value
            }

            val authorizationHeader = request.getHeader(AUTHORIZATION_HEADER)
            return if (!authorizationHeader.isNullOrBlank() && authorizationHeader.startsWith(BEARER_PREFIX)) {
                authorizationHeader.substring(BEARER_PREFIX.length)
            } else {
                null
            }
        }
    }

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        try {
            val token = extractToken(request)
            if (!token.isNullOrBlank()) {
                jwtProvider.validateOrThrow(token)

                val principalDetails = PrincipalDetails(jwtProvider.getOpaqueId(token))

                // todo : TokenService로 분리 필요.
                val authentication = UsernamePasswordAuthenticationToken(
                    principalDetails,
                    null,
                    principalDetails.authorities
                )
                SecurityContextHolder.getContext().authentication = authentication
            }
        } catch (e: JwtException) {
            log.debug(e) { "JWT 인증 실패: ${e.message}" }
        } catch (e: Exception) {
            log.debug(e) { "JWT 필터 처리 중 예외 발생: ${e.message}" }
        }

        filterChain.doFilter(request, response)
    }
}
