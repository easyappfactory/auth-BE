package com.wq.auth.web.common.response

import com.fasterxml.jackson.annotation.JsonInclude
import com.wq.auth.shared.error.ApiResponseCode
import io.swagger.v3.oas.annotations.media.Schema

@JsonInclude(JsonInclude.Include.NON_NULL)
data class CommonResponse<T>(
    @get:Schema(description = "요청 성공 여부", example = "true")
    val success: Boolean,

    @get:Schema(description = "응답 코드", example = "SUCCESS")
    val code: String,

    @get:Schema(description = "응답 메시지", example = "요청이 성공적으로 처리되었습니다.")
    val message: String,

    @get:Schema(description = "응답 데이터")
    val data: T? = null
) {
    companion object {
        private const val SUCCESS_CODE = "SUCCESS"
        private const val DEFAULT_SUCCESS_MESSAGE = "요청이 성공적으로 처리되었습니다."

        fun <T> success(
            message: String = DEFAULT_SUCCESS_MESSAGE,
            data: T? = null
        ): CommonResponse<T> = CommonResponse(
            success = true,
            code = SUCCESS_CODE,
            message = message,
            data = data
        )

        fun fail(code: ApiResponseCode): CommonResponse<Unit> = CommonResponse(
            success = false,
            code = code.toString(),
            message = code.message,
            data = null
        )

        fun fail(code: String, message: String): CommonResponse<Unit> = CommonResponse(
            success = false,
            code = code,
            message = message,
            data = null
        )
    }
}
