package com.wq.auth.shared.rateLimiter

import com.wq.auth.shared.error.CommonExceptionCode
import com.wq.auth.shared.rateLimiter.annotation.RateLimit
import com.wq.auth.web.common.response.CommonResponse
import io.github.oshai.kotlinlogging.KotlinLogging
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.HttpStatus
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.method.HandlerMethod
import org.springframework.web.servlet.HandlerInterceptor
import tools.jackson.databind.json.JsonMapper
import java.time.Duration
import java.util.concurrent.TimeUnit

@Component
class RateLimiterInterceptor(
    private val rateLimiter: TokenBucketRateLimiter,
    private val jsonMapper: JsonMapper
) : HandlerInterceptor {

    private val log = KotlinLogging.logger {}

    override fun preHandle(
        request: HttpServletRequest,
        response: HttpServletResponse,
        handler: Any
    ): Boolean {
        // Controller 메서드가 아니면 통과
        if (handler !is HandlerMethod) {
            return true
        }

        // @RateLimit 어노테이션 확인
        val rateLimit = handler.getMethodAnnotation(RateLimit::class.java)
            ?: return true

        // 버킷 키. 인증된 요청은 opaqueId 를 쓴다.
        //
        // 인증 전 요청(만료된 AT 로 introspect → silent refresh)은 SecurityContext 가 비어 있다.
        // 그대로 "anonymous" 를 쓰면 전 사용자가 버킷 하나(60회/분)를 공유하게 되어,
        // AT 만료 직후 트래픽이 몰리면 무관한 사용자들이 429 를 맞는다. 그래서 IP 로 나눈다.
        val bucketKey = SecurityContextHolder.getContext()
            .authentication?.name
            ?: clientIpOf(request)

        // Duration 변환. 기본은 분
        val duration = when (rateLimit.timeUnit) {
            TimeUnit.SECONDS -> Duration.ofSeconds(rateLimit.duration)
            TimeUnit.MINUTES -> Duration.ofMinutes(rateLimit.duration)
            TimeUnit.HOURS -> Duration.ofHours(rateLimit.duration)
            else -> Duration.ofMinutes(rateLimit.duration)
        }

        return if (rateLimiter.allowRequest(bucketKey, rateLimit.limit, duration)) {
            true
        } else {
            //429
            response.status = HttpStatus.TOO_MANY_REQUESTS.value()
            response.contentType = "application/json;charset=UTF-8"

            val limitMessage = "최대 ${rateLimit.limit}회 / ${rateLimit.duration}${rateLimit.timeUnit.name.lowercase()} 제한을 초과했습니다."

            val failResponse = CommonResponse.fail(
                CommonExceptionCode.RATE_LIMIT_EXCEEDED.toString(),
                limitMessage
            )

            response.writer.write(jsonMapper.writeValueAsString(failResponse))

            log.info{"Rate limit exceeded: bucketKey=$bucketKey, endpoint=${request.requestURI}"}
            false
        }
    }

    /**
     * 인증 전 요청의 레이트리밋 버킷 키.
     *
     * 이 서비스는 게이트웨이 뒤에 있어 remoteAddr 이 게이트웨이 IP 로 고정된다.
     * 그러면 다시 전 사용자가 버킷 하나를 공유하게 되므로 X-Forwarded-For 를 먼저 본다.
     */
    private fun clientIpOf(request: HttpServletRequest): String =
        request.getHeader("X-Forwarded-For")
            ?.split(",")
            ?.firstOrNull()
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
            ?: request.remoteAddr
            ?: "anonymous"
}
