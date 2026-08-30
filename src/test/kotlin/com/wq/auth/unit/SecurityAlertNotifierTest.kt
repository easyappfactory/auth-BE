package com.wq.auth.unit

import com.sun.net.httpserver.HttpServer
import com.wq.auth.shared.alert.SecurityAlertNotifier
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import org.springframework.web.client.RestClient
import java.net.InetSocketAddress
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * 실제 HTTP 요청이 나가는지 로컬 스텁 서버로 확인한다.
 *
 * 목킹만 하면 "호출했다"까지만 알 수 있고, **실제로 어떤 본문이 어떤 헤더로 나가는지**는
 * 모른다. Google Chat 은 `{"text": "..."}` 형태를 요구하므로 그 계약을 여기서 고정한다.
 */
class SecurityAlertNotifierTest : StringSpec({

    /** 요청을 받아 본문을 기록하는 최소 스텁 서버 */
    class Stub(status: Int = 200) {
        val server: HttpServer = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        @Volatile var body: String? = null
        @Volatile var contentType: String? = null
        @Volatile var method: String? = null
        val received = CountDownLatch(1)

        init {
            server.createContext("/hook") { ex ->
                method = ex.requestMethod
                contentType = ex.requestHeaders.getFirst("Content-Type")
                body = ex.requestBody.readBytes().decodeToString()
                ex.sendResponseHeaders(status, -1)
                ex.close()
                received.countDown()
            }
            server.start()
        }

        val url: String get() = "http://127.0.0.1:${server.address.port}/hook"
        fun awaitRequest() = received.await(5, TimeUnit.SECONDS)
        fun stop() = server.stop(0)
    }

    fun notifier(url: String) = SecurityAlertNotifier(
        restClient = RestClient.create(),
        webhookUrl = url,
        environment = "test",
    )

    "웹훅으로 Google Chat 형식의 JSON 을 POST 한다" {
        val stub = Stub()
        try {
            notifier(stub.url).refreshTokenReuseDetected(
                opaqueId = "550e8400-e29b-41d4-a716-446655440000",
                jti = "stolen-jti",
                rotatedAt = Instant.parse("2026-08-30T12:00:00Z"),
            )

            stub.awaitRequest() shouldBe true
            stub.method shouldBe "POST"
            stub.contentType shouldContain "application/json"

            val body = stub.body!!
            // Google Chat 은 text 필드를 요구한다
            body shouldContain "\"text\""
            body shouldContain "RT 재사용 감지"
            // alpha 와 prod 가 같은 채널을 공유하므로 환경이 제목에 드러나야 한다
            body shouldContain "[TEST]"
            body shouldContain "550e8400-e29b-41d4-a716-446655440000"
            body shouldContain "stolen-jti"
            body shouldContain "2026-08-30T12:00:00Z"
            // 조사 지침이 메시지에 들어 있어야 알림을 받은 사람이 판단할 수 있다
            body shouldContain "동시다발"
        } finally {
            stub.stop()
        }
    }

    "메시지에 웹훅 URL 이나 토큰 값이 실리지 않는다" {
        val stub = Stub()
        try {
            notifier(stub.url).refreshTokenReuseDetected("user-1", "jti-1", Instant.now())
            stub.awaitRequest() shouldBe true

            val body = stub.body!!
            // 알림 채널로 자격증명이 새면 알림 자체가 사고가 된다
            body shouldNotContain "127.0.0.1"
            body shouldNotContain "/hook"
        } finally {
            stub.stop()
        }
    }

    "채널이 5xx 를 돌려줘도 예외를 밖으로 내보내지 않는다" {
        // 알림 실패가 인증 실패가 되면 안 된다.
        val stub = Stub(status = 500)
        try {
            notifier(stub.url).refreshTokenReuseDetected("user-1", "jti-1", null)
            stub.awaitRequest() shouldBe true
        } finally {
            stub.stop()
        }
    }

    "웹훅 URL 이 없으면 전송을 건너뛰고 예외도 던지지 않는다" {
        // 설정이 없어도 기동·동작해야 한다. 알림만 빠진다.
        notifier("").refreshTokenReuseDetected("user-1", "jti-1", null)
    }

    "연결할 수 없는 주소여도 예외를 밖으로 내보내지 않는다" {
        // 포트 1은 열려 있지 않다
        notifier("http://127.0.0.1:1/hook").refreshTokenReuseDetected("user-1", "jti-1", null)
    }
})
