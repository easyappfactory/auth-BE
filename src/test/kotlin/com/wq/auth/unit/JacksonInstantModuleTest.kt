package com.wq.auth.unit

import com.wq.auth.shared.time.ZoneProvider
import io.kotest.core.spec.style.StringSpec
import java.time.Instant
import java.time.ZoneId
import tools.jackson.databind.module.SimpleModule
import tools.jackson.databind.json.JsonMapper
import com.wq.auth.shared.time.InstantFromIsoDeserializer
import com.wq.auth.shared.time.InstantToZoneSerializer
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

/**
 * InstantToZoneSerializer / InstantFromIsoDeserializer 단위 테스트.
 *
 * Spring Boot 4는 Jackson 3.x(tools.jackson.*)를 사용하므로 JsonMapper와
 * tools.jackson.databind.module.SimpleModule을 직접 사용합니다.
 */
class JacksonInstantModuleTest : StringSpec({

    fun mapperWith(zoneId: String): JsonMapper {
        val zoneProvider = object : ZoneProvider {
            override fun zoneId(): ZoneId = ZoneId.of(zoneId)
        }
        val module = SimpleModule().apply {
            addSerializer(Instant::class.java, InstantToZoneSerializer(zoneProvider))
            addDeserializer(Instant::class.java, InstantFromIsoDeserializer())
        }
        return JsonMapper.builder()
            .addModule(module)
            .build()
    }

    "Instant → JSON 직렬화 시 Asia/Seoul(+09:00)로 변환된다" {
        val mapper = mapperWith("Asia/Seoul")
        val instant = Instant.parse("2025-08-12T00:00:00Z")

        val json = mapper.writeValueAsString(mapOf("at" to instant))
        json shouldContain "\"at\":\"2025-08-12T09:00:00+09:00\""
    }

    "Instant → JSON 직렬화 시 Europe/Paris(+02:00 또는 +01:00)로 변환된다" {
        val mapper = mapperWith("Europe/Paris")
        val instant = Instant.parse("2025-08-12T00:00:00Z")

        val json = mapper.writeValueAsString(mapOf("at" to instant))
        json shouldContain "+02:00" // 8월은 CEST(+02:00)
    }

    "오프셋 포함 ISO 문자열 → Instant(UTC)로 역직렬화된다" {
        val mapper = mapperWith("Asia/Seoul")
        val json = """{"at":"2025-08-12T09:00:00+09:00"}"""

        val node = mapper.readTree(json)
        val inst = mapper.treeToValue(node.get("at"), Instant::class.java)

        inst shouldBe Instant.parse("2025-08-12T00:00:00Z")
    }

    "UTC(Z) 문자열 → Instant(UTC)로 역직렬화된다" {
        val mapper = mapperWith("Asia/Seoul")
        val json = """{"at":"2025-08-12T00:00:00Z"}"""

        val node = mapper.readTree(json)
        val inst = mapper.treeToValue(node.get("at"), Instant::class.java)

        inst shouldBe Instant.parse("2025-08-12T00:00:00Z")
    }
})
