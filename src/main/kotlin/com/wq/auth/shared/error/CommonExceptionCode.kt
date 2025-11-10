package com.wq.auth.shared.error

/**
 * 공통 에러 응답 코드
 * ex) 서버, 인프라 에러 등.
 */
enum class CommonExceptionCode(
    override val status: Int,
    override val message: String
) : ApiResponseCode {
    INTERNAL_SERVER_ERROR(500, "서버 내부에 문제가 발생했습니다. 다시 시도해주세요."),
    RATE_LIMIT_EXCEEDED(429,"요청 횟수 제한을 초과했습니다. 잠시 후 다시 시도해 주세요.")
}