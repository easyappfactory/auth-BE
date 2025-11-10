package com.wq.auth.shared.rateLimiter

import io.github.bucket4j.Bandwidth
import io.github.bucket4j.Bucket
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import java.util.concurrent.ConcurrentHashMap
import java.time.Duration

@Component
class TokenBucketRateLimiter {
    private val buckets = ConcurrentHashMap<String, BucketWithTimestamp>()

    // 타임스탬프 포함 Bucket
    data class BucketWithTimestamp(
        val bucket: Bucket,
        var lastAccessTime: Long = System.currentTimeMillis()
    )

    // 메모리 정리
    // TODO
    // Redis 연동 추천
    @Scheduled(fixedRate = 300000) // 5분마다 실행
    fun cleanupOldBuckets() {
        val now = System.currentTimeMillis()
        val threshold = 3600000 // 1시간

        buckets.entries.removeIf { (_, value) ->
            now - value.lastAccessTime > threshold
        }
    }

    fun allowRequest(
        userId: String,
        limit: Int = 100,
        duration: Duration = Duration.ofMinutes(1)
    ): Boolean {
        val key = "$userId:$limit:${duration.toMillis()}"

        val bucketWrapper = buckets.computeIfAbsent(key) {
            BucketWithTimestamp(
                Bucket.builder()
                    .addLimit(
                        Bandwidth.builder()
                            .capacity(limit.toLong())
                            .refillIntervally(limit.toLong(), duration)
                            .build()
                    )
                    .build()
            )
        }

        // 마지막 접근 시간 업데이트
        bucketWrapper.lastAccessTime = System.currentTimeMillis()

        return bucketWrapper.bucket.tryConsume(1)
    }
}