package com.wq.auth.shared.rateLimiter

import com.fasterxml.jackson.databind.ObjectMapper
import com.wq.auth.shared.error.CommonExceptionCode
import com.wq.auth.shared.rateLimiter.annotation.RateLimit
import com.wq.auth.web.common.response.FailResponse
import io.github.oshai.kotlinlogging.KotlinLogging
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.HttpStatus
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.method.HandlerMethod
import org.springframework.web.servlet.HandlerInterceptor
import java.time.Duration
import java.util.concurrent.TimeUnit

@Component
class RateLimiterInterceptor(
    private val rateLimiter: TokenBucketRateLimiter,
    private val objectMapper: ObjectMapper
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

        // 유저 OpaqueId 가져오기
        val userOpaqueId = SecurityContextHolder.getContext()
            .authentication?.name ?: "anonymous"

        // Duration 변환. 기본은 분
        val duration = when (rateLimit.timeUnit) {
            TimeUnit.SECONDS -> Duration.ofSeconds(rateLimit.duration)
            TimeUnit.MINUTES -> Duration.ofMinutes(rateLimit.duration)
            TimeUnit.HOURS -> Duration.ofHours(rateLimit.duration)
            else -> Duration.ofMinutes(rateLimit.duration)
        }

        return if (rateLimiter.allowRequest(userOpaqueId, rateLimit.limit, duration)) {
            true
        } else {
            //429
            response.status = HttpStatus.TOO_MANY_REQUESTS.value()
            response.contentType = "application/json;charset=UTF-8"

            val limitMessage = "최대 ${rateLimit.limit}회 / ${rateLimit.duration}${rateLimit.timeUnit.name.lowercase()} 제한을 초과했습니다."

            val failResponse = FailResponse(
                success = false,
                message = limitMessage,
                error = CommonExceptionCode.RATE_LIMIT_EXCEEDED.toString()
            )

            response.writer.write(objectMapper.writeValueAsString(failResponse))

            log.info{"Rate limit exceeded: userOpaqueId=$userOpaqueId, endpoint=${request.requestURI}"}
            false
        }
    }
}
