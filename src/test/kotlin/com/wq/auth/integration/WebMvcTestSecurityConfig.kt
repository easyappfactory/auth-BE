package com.wq.auth.integration

import com.wq.auth.security.jwt.error.JwtExceptionCode
import com.wq.auth.security.principal.PrincipalDetails
import com.wq.auth.web.common.response.CommonResponse
import jakarta.servlet.http.HttpServletRequest
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.core.MethodParameter
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.InsufficientAuthenticationException
import org.springframework.security.core.Authentication
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import org.springframework.web.bind.support.WebDataBinderFactory
import org.springframework.web.context.request.NativeWebRequest
import org.springframework.web.method.support.HandlerMethodArgumentResolver
import org.springframework.web.method.support.ModelAndViewContainer
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer

/**
 * @WebMvcTest 슬라이스에서 @AuthenticationPrincipal PrincipalDetails 파라미터 해석을 위한
 * 테스트 전용 설정.
 *
 * Spring Boot 4 / Spring Security 7 환경에서 @WebMvcTest 컨텍스트에는
 * FilterChainProxy가 MockMvc 필터 체인에 포함되지 않아 SecurityContextHolderFilter가
 * 동작하지 않습니다. 그 결과 SecurityContextHolder가 비어 있어
 * AuthenticationPrincipalArgumentResolver가 null을 반환합니다.
 *
 * 해결책: SecurityMockMvcRequestPostProcessors.user()는 인증 정보를
 * HttpSession의 "SPRING_SECURITY_CONTEXT" 속성에 저장합니다(HttpSessionSecurityContextRepository 폴백).
 * 이를 직접 읽어 PrincipalDetails를 추출합니다.
 *
 * 미인증 요청(인증 정보 없음) → InsufficientAuthenticationException 발생 →
 * WebMvcTestAuthExceptionHandler가 401을 반환합니다.
 */
@TestConfiguration
class WebMvcTestSecurityConfig : WebMvcConfigurer {
    override fun addArgumentResolvers(resolvers: MutableList<HandlerMethodArgumentResolver>) {
        resolvers.add(0, PrincipalDetailsArgumentResolver())
    }

    @Bean
    fun webMvcTestAuthExceptionHandler(): WebMvcTestAuthExceptionHandler =
        WebMvcTestAuthExceptionHandler()
}

/**
 * @AuthenticationPrincipal 어노테이션이 달린 PrincipalDetails 파라미터를 해석합니다.
 *
 * 인증 정보 탐색 순서:
 * 1. SecurityContextHolder (필터 체인이 동작하는 경우)
 * 2. HttpSession의 SPRING_SECURITY_CONTEXT 속성
 *    (SecurityMockMvcRequestPostProcessors.user() 폴백 경로)
 *
 * 인증 정보가 없으면 InsufficientAuthenticationException을 발생시켜
 * 컨트롤러 메서드 실행 전에 401 응답이 반환되도록 합니다.
 */
class PrincipalDetailsArgumentResolver : HandlerMethodArgumentResolver {
    companion object {
        private const val SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT"
    }

    override fun supportsParameter(parameter: MethodParameter): Boolean {
        return parameter.hasParameterAnnotation(AuthenticationPrincipal::class.java) &&
            PrincipalDetails::class.java.isAssignableFrom(parameter.parameterType)
    }

    override fun resolveArgument(
        parameter: MethodParameter,
        mavContainer: ModelAndViewContainer?,
        webRequest: NativeWebRequest,
        binderFactory: WebDataBinderFactory?
    ): Any? {
        val authentication = findAuthentication(webRequest)
            ?: throw InsufficientAuthenticationException("인증 정보가 없습니다.")
        val principal = authentication.principal
        return if (principal is PrincipalDetails) principal
        else throw InsufficientAuthenticationException("유효한 PrincipalDetails가 없습니다.")
    }

    private fun findAuthentication(webRequest: NativeWebRequest): Authentication? {
        // 1. SecurityContextHolder 확인 (필터 체인이 완전히 동작할 때)
        val holderAuth = SecurityContextHolder.getContext().authentication
        if (holderAuth != null) return holderAuth

        // 2. HttpSession 확인 (SecurityMockMvcRequestPostProcessors.user() 폴백)
        val request = webRequest.getNativeRequest(HttpServletRequest::class.java) ?: return null
        val session = request.getSession(false) ?: return null
        val context = session.getAttribute(SPRING_SECURITY_CONTEXT_KEY) as? SecurityContext ?: return null
        return context.authentication
    }
}

/**
 * 테스트 전용: InsufficientAuthenticationException → 401 Unauthorized 변환기.
 *
 * 프로덕션 환경에서는 FilterChainProxy → ExceptionTranslationFilter →
 * JwtAuthenticationEntryPoint 경로로 401이 처리됩니다.
 * @WebMvcTest 슬라이스에서는 필터 체인이 없으므로, 이 어드바이스가 대신 처리합니다.
 *
 * @Order(HIGHEST_PRECEDENCE)로 GlobalExceptionHandler보다 먼저 탐색되어
 * InsufficientAuthenticationException을 가로채 401을 반환합니다.
 */
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
class WebMvcTestAuthExceptionHandler {

    @ExceptionHandler(InsufficientAuthenticationException::class)
    fun handleInsufficientAuthentication(
        e: InsufficientAuthenticationException
    ): ResponseEntity<CommonResponse<Unit>> {
        val body = CommonResponse.fail(JwtExceptionCode.TOKEN_MISSING)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body)
    }
}
