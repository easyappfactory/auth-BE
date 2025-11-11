package com.wq.auth.shared.rateLimiter.annotation

import java.util.concurrent.TimeUnit

@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
annotation class RateLimit(
    val limit: Int = 100,              // 허용 횟수
    val duration: Long = 1,             // 시간
    val timeUnit: TimeUnit = TimeUnit.MINUTES  // 단위
)