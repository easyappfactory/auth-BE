# OAuth redirect_uri 전략 (auth vs wedding)

auth.easyappfactory.com(로그인 데모)과 wedding.easyappfactory.com(실제 서비스)에서 같은 auth-BE로 OAuth 가입/로그인을 할 때, **redirect_uri를 하나로 둘지, 두 개로 둘지**와 **각각의 동작 방식**을 정리한 문서입니다.

---

## 1. 전제

- **auth.easyappfactory.com**: 로그인 데모/테스트용 페이지
- **wedding.easyappfactory.com**: 실제 웨딩 서비스
- **auth-BE**: redirect_uri를 **환경 변수 하나**만 사용 (토큰 교환 시 항상 그 값으로 요청)
- **OAuth 제공자**(Google/Kakao/Naver): 인가 요청 시 사용한 `redirect_uri`와 토큰 요청 시 사용한 `redirect_uri`가 **완전히 같아야** 코드를 인정함

---

## 2. 방법 A: redirect_uri 하나 (auth 도메인만 사용)

### 2.1 설정

- **등록/사용하는 redirect_uri**: `https://auth.easyappfactory.com/auth/naver/callback` (Google/Kakao도 동일 패턴)
- **auth-BE 환경 변수**: `NAVER_REDIRECT_URI=https://auth.easyappfactory.com/auth/naver/callback` 등 **한 개만** 설정
- Google/Kakao/Naver 개발자 콘솔에도 **이 URL 하나만** 등록

### 2.2 흐름 (wedding에서 로그인하는 경우)

```
1. 사용자: wedding.easyappfactory.com 접속
2. "네이버로 로그인" 클릭
3. [프론트] 현재 origin 저장 (예: state 또는 session에 "returnUrl=wedding.easyappfactory.com" 등)
4. [프론트] 네이버 인가 URL로 이동
   - redirect_uri = https://auth.easyappfactory.com/auth/naver/callback  (항상 auth 도메인)
   - state = (CSRF용 랜덤) + (선택) returnUrl 정보
5. 사용자가 네이버에서 로그인/동의
6. 네이버가 사용자를 리다이렉트
   → https://auth.easyappfactory.com/auth/naver/callback?code=xxx&state=xxx
7. [auth 도메인 콜백 페이지]
   - code, state 수신
   - POST api.easyappfactory.com/api/v1/auth/naver/login { authCode, state, codeVerifier }
   - 백엔드는 NAVER_REDIRECT_URI(auth 쪽)로 토큰 요청 → 성공
   - AccessToken(헤더) + RefreshToken(쿠키) 수신
8. [콜백 페이지] "wedding에서 왔는지" state/returnUrl 등으로 판단
   - wedding에서 왔으면 → window.location = "https://wedding.easyappfactory.com?loggedIn=1" 등으로 이동
   - auth 데모에서 왔으면 → auth 쪽 대시/데모 페이지로 유지
9. wedding.easyappfactory.com 도메인으로 이동했을 때
   - 쿠키는 도메인마다 다르므로, wedding에서는 RefreshToken 쿠키가 없을 수 있음
   - 이 경우 "토큰을 wedding에 전달"하는 방식을 하나 정해야 함 (아래 참고)
```

### 2.3 wedding으로 “로그인 결과” 전달하는 방법

콜백이 **auth.easyappfactory.com** 이라서, wedding과는 **쿠키/스토리지가 공유되지 않습니다**. 그래서 다음 중 하나가 필요합니다.

- **A-1. URL fragment/query로 토큰 전달**  
  - auth 콜백에서 `https://wedding.easyappfactory.com/auth/callback#access_token=xxx` 또는 `?token=xxx` 로 리다이렉트  
  - wedding의 `/auth/callback` 페이지가 토큰을 읽어서 자체 쿠키/메모리에 저장  
  - 단점: URL에 토큰이 잠깐 노출·히스토리 남음 (가능하면 fragment + 짧은 유효시간 권장)

- **A-2. postMessage / popup**  
  - wedding에서 로그인 시 **auth.easyappfactory.com** 을 팝업으로 열고, OAuth 후 auth 콜백에서 `opener.postMessage({ accessToken, ... }, "https://wedding.easyappfactory.com")` 로 전달  
  - wedding은 `message` 이벤트로 토큰 수신 후 팝업 닫기  
  - 단점: 팝업 차단·UX 고려 필요

- **A-3. wedding에서도 API 호출은 api.easyappfactory.com으로, 쿠키는 공유하지 않음**  
  - auth 콜백에서 wedding으로 리다이렉트할 때 **토큰을 URL(fragment 등)로 한 번만 전달**  
  - wedding은 그 토큰으로 API 호출하고, 필요하면 **자체 세션/쿠키**만 관리  
  - 즉 “로그인 결과”를 받는 건 wedding 한 번뿐이고, 이후는 wedding이 갖고 있는 토큰/세션만 사용

실제 서비스가 wedding이면, **A-1 또는 A-2**로 “auth 콜백 → wedding으로 토큰 전달” 한 번 정의해 두고, 이후는 wedding만 쓰는 구조가 자연스럽습니다.

### 2.4 방법 A 정리

| 장점 | 단점 |
|------|------|
| redirect_uri 하나만 등록·관리 | wedding으로 넘길 때 토큰 전달 방식 필요 |
| auth-BE 수정 불필요 (현재 구조 그대로) | auth 콜백 페이지가 “returnUrl/state 처리 + wedding 리다이렉트” 로직 필요 |
| 제공자 콘솔 설정 단순 | |

---

## 3. 방법 B: redirect_uri 두 개 (auth + wedding 각각)

### 3.1 설정

- **등록하는 redirect_uri**  
  - `https://auth.easyappfactory.com/auth/naver/callback`  
  - `https://wedding.easyappfactory.com/auth/naver/callback`
- Google/Kakao/Naver 개발자 콘솔에 **두 URL 모두** 등록
- **auth-BE**: 토큰 교환 시 “인가 요청에서 썼던 redirect_uri”를 그대로 써야 하므로, **클라이언트가 썼던 redirect_uri를 API로 받아서** 토큰 요청에 넣어줘야 함 (지금은 환경 변수 하나만 사용)

### 3.2 흐름 (wedding에서 로그인하는 경우)

```
1. 사용자: wedding.easyappfactory.com 에서 "네이버로 로그인"
2. [프론트] redirect_uri = https://wedding.easyappfactory.com/auth/naver/callback
3. 네이버 인가 → 로그인 후 wedding 도메인으로 리다이렉트
4. wedding.easyappfactory.com/auth/naver/callback 에서 code 수신
5. [프론트] POST /api/v1/auth/naver/login
   - body: { authCode, state, codeVerifier, redirectUri: "https://wedding.easyappfactory.com/auth/naver/callback" }  ← 추가 필요
6. [auth-BE] Naver 토큰 요청 시 이 redirectUri 사용 (현재는 미지원)
7. 토큰 발급 후 쿠키/헤더 설정
   - 응답이 wedding 도메인 요청으로 오므로, Set-Cookie 도 wedding 도메인 기준 (같은 API 서버라면 보통 api.easyappfactory.com; 쿠키는 그 도메인에 설정됨)
```

### 3.3 auth-BE 변경 필요 사항

- **NaverSocialLoginRequestDto** 등에 `redirectUri: String?` (또는 필수) 추가
- **NaverOAuthClient.getAccessToken** (및 Google/Kakao 동일) 호출 시, 클라이언트가 보낸 `redirectUri`를 사용하거나, 없으면 환경 변수 fallback
- 제공자별로 “등록된 redirect_uri 목록” 검증을 넣으면 보안상 좋음 (지금은 생략 가능)

### 3.4 방법 B 정리

| 장점 | 단점 |
|------|------|
| wedding에서 로그인 시 콜백이 wedding이라, 토큰/쿠키를 같은 도메인에서 바로 처리하기 쉬움 | auth-BE 수정 필요 (redirect_uri를 요청에서 받아서 토큰 교환에 사용) |
| “auth로 갔다가 다시 wedding으로 보내기” 로직 불필요 | 제공자 콘솔에 redirect_uri 두 개 등록·갱신 필요 |
| 데모(auth)와 실제 서비스(wedding) 경로가 분리됨 | |

---

## 4. 어떤 방법이 더 좋은가

### 4.1 상황 정리

- **auth.easyappfactory.com** = 로그인 **데모**
- **wedding.easyappfactory.com** = **실제 서비스**
- 현재 auth-BE는 **redirect_uri 하나**만 지원

### 4.2 추천: **방법 A (redirect_uri 하나, auth 도메인)**

이유 요약:

1. **데모는 부가 기능**  
   실제 서비스는 wedding이므로, “데모(auth)와 실제(wedding)가 같은 redirect_uri를 쓰고, wedding은 콜백 후 한 번만 토큰을 받으면 된다”로 정리하는 편이 단순합니다.

2. **백엔드 수정 없음**  
   방법 B는 DTO·OAuth 클라이언트·검증 로직을 건드려야 합니다. 방법 A는 프론트/데모 쪽만 정하면 됩니다.

3. **등록/운영 단순**  
   제공자 콘솔에 redirect_uri를 **한 개만** 두고, 만료/변경 시에도 한 곳만 관리하면 됩니다.

4. **데모의 역할이 명확**  
   auth는 “로그인 플로우 보여주기 + 테스트”용이고, 실제 로그인 완료·토큰 보관은 wedding에서만 하면 됩니다.  
   wedding에서 로그인할 때도 “인가 요청·콜백은 auth URL로 통일 → auth 콜백에서 wedding으로 한 번 리다이렉트하며 토큰 전달”이면 됩니다.

### 4.3 방법 A로 갈 때 구현 요약

- **공통**
  - 모든 OAuth 시작 시 `redirect_uri = https://auth.easyappfactory.com/auth/{google|kakao|naver}/callback` 로 고정
  - auth-BE `*_REDIRECT_URI` 와 제공자 콘솔도 위 URL 하나로 통일

- **auth.easyappfactory.com (데모)**
  - 위 콜백 URL의 페이지가 code/state 수신 → auth-BE 로그인 API 호출 → 받은 토큰으로 데모 UI 표시
  - “returnUrl” 없으면 데모 페이지에 그대로 머무름

- **wedding.easyappfactory.com (실제 서비스)**
  - 로그인 시작 시 state(또는 별도 저장)에 `returnUrl=https://wedding.easyappfactory.com/...` 포함
  - OAuth 완료 후 auth 콜백에서 `returnUrl` 확인 → wedding으로 리다이렉트하면서 **토큰 전달**
  - 토큰 전달 방식: fragment (`#access_token=...`) 또는 postMessage 중 하나로 통일하고, wedding은 그걸 받아서 저장 후 사용

이렇게 하면 **redirect URL은 하나만 두고**, auth(데모)와 wedding(실제 서비스) 모두에서 가입/로그인할 수 있으며, “어떤 방법이 더 좋은지”에는 **방법 A(단일 redirect_uri + auth 콜백에서 wedding으로 전달)** 를 추천합니다.

---

## 5. 요약 표

| 구분 | 방법 A (redirect_uri 1개) | 방법 B (redirect_uri 2개) |
|------|---------------------------|----------------------------|
| redirect_uri | auth.easyappfactory.com 만 사용 | auth + wedding 각각 등록 |
| auth-BE 변경 | 없음 | redirect_uri를 요청에서 받아서 사용하도록 수정 |
| wedding 로그인 후 | auth 콜백 → wedding으로 리다이렉트 + 토큰 전달 | wedding 콜백에서 바로 처리 |
| 추천 | **데모(auth) + 실제(wedding) 구조에 적합** | wedding 단독 앱처럼 쓸 때 유리 |
