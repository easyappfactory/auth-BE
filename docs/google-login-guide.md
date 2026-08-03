안드로이드 앱 전용 구글 로그인 기능 구현을 위해 백엔드(Spring Boot) 개발자가 진행해야 할 전체 프로세스를 요약해 드립니다.

---

## 1. 아키텍처 및 정책 요약

* **방식:** 웹의 인가 코드(Code) 방식이 아닌, 앱에서 직접 구글의 **ID Token**을 받아와 백엔드로 전달하는 방식 (구글 Credential Manager 활용).
* **API 엔드포인트:** `POST /api/v1/auth/google/login/app`
* **플랫폼 식별 헤더:** `X-Client-Id: easy-snap-and-app`
* **응답 정책:** 앱이므로 인증 성공 시 JWT(AT, RT)를 **JSON Body**에 담아 응답합니다. (웹은 쿠키 사용)
* **토큰 수명 (권장):** App 특성을 고려해 AT는 1~2시간, RT는 14~30일 이상으로 웹보다 길게 설정하고 **Sliding Window(슬라이딩 윈도우)** 연장 방식을 적용합니다.

---

## 2. 사전 준비 (Google Console & 라이브러리)

1. **Google Cloud Console 확인:**
* 앱 인증이라도 서버에서 ID Token을 검증하기 위해서는 보통 **Web Client ID**가 필요합니다. 이 ID 값을 서버 코드에 복사해 둡니다.


2. **의존성 추가 (`build.gradle.kts`):**
* 구글의 ID Token을 서버에서 자체 검증하기 위해 공식 라이브러리를 추가합니다.


```kotlin
implementation("com.google.api-client:google-api-client:2.2.0")

```



---

## 3. 백엔드 핵심 구현 단계 (Hexagonal Architecture 권장)

### Step 1: 클라이언트 식별 처리 (Interceptor / Proxy)

* 모든 요청에서 `X-Client-Id`를 확인합니다.
* `easy-snap-and-app`이 들어왔을 때 유효한 앱 클라이언트인지 검증하고, 이 요청은 "토큰을 Body로 내려줘야 하는 요청"임을 서버 내부 컨텍스트에 기록합니다.

### Step 2: API 엔드포인트 생성 (Inbound Adapter)

* `@RequestMapping`을 사용하지 않고 전체 경로를 메서드에 명시합니다.

```kotlin
@PostMapping("/api/v1/auth/google/login/app")
fun loginWithApp(
    @RequestHeader("X-Client-Id") clientId: String,
    @RequestBody request: GoogleAppLoginRequest // idToken을 포함하는 DTO
): ResponseEntity<LoginResponse> { ... }

```

### Step 3: 구글 ID Token 검증 (Application Service)

* 앱에서 넘겨받은 긴 문자열(`idToken`)이 조작되지 않았는지 구글 라이브러리로 검증합니다. 서버가 구글 서버로 다시 요청을 보낼 필요가 없습니다.

```kotlin
val verifier = GoogleIdTokenVerifier.Builder(NetHttpTransport(), GsonFactory())
    .setAudience(listOf("구글_콘솔에서_가져온_Web_Client_ID"))
    .build()

val idToken: GoogleIdToken = verifier.verify(idTokenString) 
    ?: throw InvalidTokenException("유효하지 않은 구글 토큰입니다.")

```

### Step 4: 사용자 정보 추출 및 매핑 (Business Logic)

* 검증이 끝난 토큰에서 사용자 정보(Payload)를 꺼냅니다.

```kotlin
val payload = idToken.payload
val email = payload.email
val googleSub = payload.subject // 구글 고유 유니크 ID

```

* 해당 이메일로 기존 DB를 조회하여, 이미 가입된 회원이면 로그인을 진행하고, 없다면 새로 회원가입 처리를 합니다.

### Step 5: 자체 토큰 발급 및 응답 생성

* 인증이 완료된 사용자에 대해 우리 서비스만의 Access Token(AT)과 Refresh Token(RT)을 생성합니다.
* 토큰 정보가 담긴 `LoginResponse` DTO를 **JSON Body**로 묶어 클라이언트(안드로이드 앱)에 반환합니다.

---

## 4. 기존 시스템과의 공존 (Migration Strategy)

* **웹 (기존):** 여전히 브라우저 기반의 인가 코드(Code) 방식을 사용하며, 서버가 구글 서버와 통신 후 응답은 쿠키로 내려줍니다.
* **앱 (신규):** `/login/app` 경로를 통해 **ID Token** 검증 방식을 독립적으로 수행하므로 기존 웹 로그인 로직(`auth/google/login` 등)의 코드를 건드릴 필요가 없습니다.

```</LoginResponse>

```