package com.wq.auth.shared.time

import org.springframework.stereotype.Component
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZonedDateTime

/** 저장/계산용 'UTC 시계' */
@Component
class TimeProvider(
    private val clock: Clock = Clock.systemUTC()
) {
    fun nowInstant(): Instant = Instant.now(clock)                       // 가장 안전한 저장 타입

    fun at(zone: ZoneId): ZonedDateTime = nowInstant().atZone(zone)
}