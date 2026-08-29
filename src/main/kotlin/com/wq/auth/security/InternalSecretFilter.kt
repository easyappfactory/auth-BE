package com.wq.auth.security

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.security.MessageDigest

/**
 * `/internal-api/` 하위 전체를 `X-Internal-Secret` 헤더로 강제 보호한다.
 *
 * 기존에는 이 확인이 [com.wq.auth.api.controller.internal.InternalMemberController] 의
 * **메서드 안에** 있었다. 컨트롤러가 하나뿐인 지금은 문제가 없지만, 새 내부 컨트롤러를
 * 추가하면서 확인을 빠뜨리면 그대로 노출되는 구조다. SecurityConfig 에서
 * `/internal-api/` 하위 전체는 permitAll 이기 때문이다.
 *
 * 경로 단위로 강제되도록 필터로 올린다. 컨트롤러 내부의 기존 검사는 이중 방어로 남긴다.
 */
@Component
class InternalSecretFilter(
    @Value("\${app.internal.secret}") private val secret: String,
) : OncePerRequestFilter() {

    override fun shouldNotFilter(request: HttpServletRequest): Boolean =
        !request.requestURI.startsWith("/internal-api/")

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        val provided = request.getHeader("X-Internal-Secret")?.toByteArray() ?: ByteArray(0)
        // 문자열 != 가 아니라 상수시간 비교를 쓴다.
        // 일반 비교는 앞에서부터 다른 문자를 만나면 즉시 반환하므로,
        // 응답 시간 차이로 시크릿을 한 글자씩 추측당할 수 있다.
        if (!MessageDigest.isEqual(provided, secret.toByteArray())) {
            logger.warn("[internal-api] X-Internal-Secret 불일치 - ${request.requestURI}")
            response.status = HttpStatus.FORBIDDEN.value()
            return
        }
        filterChain.doFilter(request, response)
    }
}
