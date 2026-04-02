package com.wq.auth.web.common

import com.wq.auth.shared.error.ApiException
import com.wq.auth.shared.error.CommonExceptionCode
import com.wq.auth.security.jwt.error.JwtExceptionCode
import com.wq.auth.web.common.response.CommonResponse
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.authorization.AuthorizationDeniedException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice

@RestControllerAdvice
class GlobalExceptionHandler {

    companion object {
        private val log: Logger = LoggerFactory.getLogger(GlobalExceptionHandler::class.java)
    }

    @ExceptionHandler(ApiException::class)
    fun handleApiException(e: ApiException): ResponseEntity<CommonResponse<Unit>> {

        log.error(e.extractExceptionLocation() + e.message)
        val status = HttpStatus.valueOf(e.code.status)
        val body = CommonResponse.fail(e.code)
        return ResponseEntity.status(status).body(body)
    }

    @ExceptionHandler(AuthorizationDeniedException::class)
    fun handleAuthorizationDenied(e: AuthorizationDeniedException): ResponseEntity<CommonResponse<Unit>> {
        log.warn("[권한 부족] ${e.message}")
        val status = HttpStatus.FORBIDDEN
        val body = CommonResponse.fail(JwtExceptionCode.FORBIDDEN)
        return ResponseEntity.status(status).body(body)
    }

    // 예상 못 한 예외 처리
    @ExceptionHandler(Exception::class)
    fun handleUnexpected(e: Exception): ResponseEntity<CommonResponse<Unit>> {
        log.error("[예상치 못한 예외 발생] $e")
        val status = HttpStatus.INTERNAL_SERVER_ERROR
        val body = CommonResponse.fail(
            CommonExceptionCode.INTERNAL_SERVER_ERROR
        )
        return ResponseEntity.status(status).body(body)
    }
}