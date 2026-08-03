package com.wq.auth.shared.time

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import tools.jackson.core.JsonGenerator
import tools.jackson.core.JsonParser
import tools.jackson.databind.DeserializationContext
import tools.jackson.databind.SerializationContext
import tools.jackson.databind.ValueDeserializer
import tools.jackson.databind.ValueSerializer
import tools.jackson.databind.module.SimpleModule
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

private val ISO_WITH_SECONDS: DateTimeFormatter =
    DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX")

/** Instant -> ISO-8601(+offset)로 ZoneProvider 기준 변환 */
class InstantToZoneSerializer(
    private val zoneProvider: ZoneProvider
) : ValueSerializer<Instant>() {
    override fun serialize(value: Instant?, gen: JsonGenerator, ctxt: SerializationContext) {
        if (value == null) { gen.writeNull(); return }
        val offset = value
            .atZone(ZoneOffset.UTC)
            .withZoneSameInstant(zoneProvider.zoneId())
            .toOffsetDateTime()
        gen.writeString(ISO_WITH_SECONDS.format(offset)) // ← 항상 HH:mm:ss 출력
    }
}

/** ISO 문자열 -> Instant (요청 바디 수신 시) */
class InstantFromIsoDeserializer : ValueDeserializer<Instant>() {
    override fun deserialize(p: JsonParser, ctxt: DeserializationContext): Instant {
        val s = p.getString()
        return runCatching { OffsetDateTime.parse(s).toInstant() }
            .getOrElse { Instant.parse(s) }
    }
}

/**
 * Jackson에 커스텀 Serializer/Deserializer를 등록하는 설정 클래스
 *
 * Spring Boot 4는 Jackson 3.x(tools.jackson.*)를 사용하므로,
 * ValueSerializer / ValueDeserializer 및 tools.jackson.databind.module.SimpleModule을 사용합니다.
 */
@Configuration
class JacksonTimeConfig(private val zoneProvider: ZoneProvider) {
    @Bean
    fun instantZoneModule(): SimpleModule =
        SimpleModule().apply {
            addSerializer(Instant::class.java, InstantToZoneSerializer(zoneProvider))
            addDeserializer(Instant::class.java, InstantFromIsoDeserializer())
        }
}
