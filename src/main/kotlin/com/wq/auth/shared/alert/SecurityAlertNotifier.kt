package com.wq.auth.shared.alert

import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.scheduling.annotation.Async
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient
import java.time.Instant

/**
 * 보안 이벤트를 운영 알림 채널(Google Chat)로 보낸다.
 *
 * **설계 원칙 — 알림은 절대 본 요청을 방해하지 않는다.**
 *  - `@Async` — 인증 요청 스레드를 잡지 않는다. 동기로 부르면 채널이 느릴 때
 *    사용자의 로그인·갱신이 함께 느려지고, 호출부가 `@Transactional` 이라
 *    **DB 트랜잭션이 네트워크 왕복만큼 열린 채로 유지된다.**
 *  - **어떤 예외도 밖으로 내보내지 않는다.** 알림 실패가 인증 실패가 되면 안 된다.
 *  - 타임아웃은 주입되는 [RestClient] 빈이 갖고 있다(연결 3초 / 응답 3초).
 *
 * **웹훅 URL 은 그 자체가 시크릿이다.** 아는 사람은 누구나 그 채널에 글을 쓸 수 있다.
 * 로그에 찍지 않으며, 비어 있으면 전송을 건너뛰고 경고만 남긴다(설정 없이도 기동한다).
 *
 * **메시지에 자격증명을 넣지 않는다.** 토큰 값·시크릿은 담지 않는다.
 * 알림 채널로 자격증명이 새면 알림이 사고가 된다.
 */
@Component
class SecurityAlertNotifier(
    private val restClient: RestClient,
    @Value("\${app.alert.security-chat-webhook-url:}")
    private val webhookUrl: String,
    @Value("\${spring.profiles.active:local}")
    private val environment: String,
) {
    private val log = KotlinLogging.logger {}

    /**
     * RT 재사용(도난 정황) 통지.
     *
     * @param opaqueId 대상 사용자 식별자 (UUID — 이메일·이름 등은 담지 않는다)
     * @param jti 재사용된 RefreshToken 의 식별자 (토큰 값이 아니다)
     * @param rotatedAt 그 jti 가 회전(폐기)된 시각. null 이면 알 수 없음
     */
    fun refreshTokenReuseDetected(opaqueId: String, jti: String, rotatedAt: Instant?) {
        val text = buildString {
            append("🚨 *RT 재사용 감지 — 계정 탈취 정황*\n")
            append("환경: `$environment`\n")
            append("사용자: `$opaqueId`\n")
            append("재사용된 jti: `$jti`\n")
            append("해당 jti 회전 시각: `${rotatedAt ?: "알 수 없음"}`\n")
            append("감지 시각: `${Instant.now()}`\n")
            append("\n")
            append("이미 자동 조치됨 — 해당 계정의 RefreshToken 전량 폐기 + AccessToken 무효화. ")
            append("사용자는 재로그인이 필요합니다.\n")
            append("확인할 것: 같은 사용자에게 반복되는지, *여러 사용자에게 동시다발인지*. ")
            append("후자면 토큰 유출 경로 자체를 의심해야 합니다.")
        }
        send(text)
    }

    /** 전송 실패는 로그로만 남긴다. 호출부로 예외가 나가지 않는다. */
    @Async
    fun send(text: String) {
        if (webhookUrl.isBlank()) {
            log.warn { "보안 알림 미전송 — app.alert.security-chat-webhook-url(SECURITY_ALERT_CHAT_WEBHOOK_URL)이 설정되지 않았습니다." }
            return
        }
        try {
            restClient.post()
                .uri(webhookUrl)
                .contentType(MediaType.APPLICATION_JSON)
                .body(mapOf("text" to text))
                .retrieve()
                .toBodilessEntity()
        } catch (e: Exception) {
            // URL 은 시크릿이므로 로그에 남기지 않는다.
            log.error(e) { "보안 알림 전송 실패: ${e.message}" }
        }
    }
}
