package com.wq.auth.security

import com.wq.auth.security.jwt.error.JwtExceptionCode
import com.wq.auth.web.common.response.CommonResponse
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.http.MediaType
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.stereotype.Component
import tools.jackson.databind.json.JsonMapper
import java.nio.charset.StandardCharsets

/**
 * JWT 기반 인증에서 403 Forbidden 에러를 처리하는 핸들러
 * : 인증은 성공했지만 권한이 부족한 경우 (예: 일반 사용자가 관리자 API 접근) 호출됩니다.
 */
@Component
class JwtAccessDeniedHandler(
    private val jsonMapper: JsonMapper
) : AccessDeniedHandler {

    private val log = KotlinLogging.logger {}

    override fun handle(
        request: HttpServletRequest,
        response: HttpServletResponse,
        accessDeniedException: AccessDeniedException
    ) {
        // 로그 출력 (백엔드 전용)
        log.debug { "[403] Access denied: ${request.method} ${request.requestURI} - Reason: ${accessDeniedException.message}" }

        // 응답 설정
        response.status = HttpServletResponse.SC_FORBIDDEN
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        response.characterEncoding = StandardCharsets.UTF_8.name()

        // 표준 API 응답 형식으로 에러 응답 생성
        val errorResponse = CommonResponse.fail(JwtExceptionCode.FORBIDDEN)
        val jsonResponse = jsonMapper.writeValueAsString(errorResponse)

        response.writer.write(jsonResponse)
        response.writer.flush()
    }
}
