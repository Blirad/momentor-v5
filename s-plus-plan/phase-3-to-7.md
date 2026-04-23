# Phase 3 — 인감 의식 (Seal Ritual)

## 3-1. 다단계 캡처 시퀀스

```
클릭 →
  0-300ms:   버튼 수축 + CSS shake 진동
  300-800ms: 동심원 파동 3겹 확산 (cinnabar ring, scale 1→3, opacity 1→0)
  800-1500ms: 노드 순차 발광 + 연결선 동시 발광
  1500-2200ms: Canvas 파티클이 중앙으로 수렴 (인감으로 빨려듦)
  2200-2800ms: 인감 cinnabar glow 최대 → 서서히 감소
  2800ms+: 타임스탬프 typewriter 효과로 한 글자씩 표시
```

## 3-2. 인감 idle 상태

- 호흡 이중 원: inner border + outer glow 비동기 pulse
- 미세 부유감: translateY 2px oscillation (6초 주기)
- 대기 중 연결선에 미세 빛점 순환 유지

---

# Phase 4 — 입장 연출 (Entrance Choreography)

## 4-1. 시네마틱 시퀀스 (3.2초)

```
0ms:      검은 화면
200ms:    잉크 워시 번짐 (scale 0.5→1, opacity 0→1)
600ms:    그레인 텍스처 fade-in
800ms:    중앙 축이 위→아래로 그어짐 (stroke animation)
1000ms:   노드 1-2 등장 (fade + scale 0.8→1)
1200ms:   노드 3-4 등장
1400ms:   노드 5-6 등장
1600ms:   노드 7-8 등장
1800ms:   연결선 stroke-dashoffset으로 그어짐
2000ms:   인감 등장 (scale 0→1 + rotation 90°→0°)
2200ms:   좌표 텍스트 typewriter
2500ms:   좌/우 패널 fade-in
2800ms:   상/하 celestial nav fade-in
3000ms:   학 SVG fade-in (또는 에칭 장식)
3200ms:   파티클 시작
```

## 4-2. 구현 방식

- CSS @keyframes + animation-delay 로 순차 제어
- JS로 클래스 토글: `.scene-ready` → 각 요소에 staggered reveal
- prefers-reduced-motion 존중: 애니메이션 즉시 완료

---

# Phase 5 — 실시간 데이터 & 디테일

## 5-1. 라이브 시계

- 하단 nav에 HH:MM:SS 실시간 시계 (mono font, 매초 갱신)
- 콜론(:) 이 1초 주기로 blink

## 5-2. 월상 동적 계산

- 현재 날짜 기반 실제 월상 계산 (synodic month 알고리즘)
- CSS clip-path + border-radius로 정확한 달 모양 렌더링
- 초승/보름/그믐 등 8단계 표현

## 5-3. Archive 아이템 호버 개선

- 호버 시: cinnabar 보더가 height 0→100%로 그어짐 (0.3초)
- 텍스트 opacity + translateX(4px) 전환
- 시간 텍스트 color: fg-muted → fg-paper 전환
- 클릭 시: 아이템이 짧게 scale(0.98) → 복귀 (tactile feedback)

## 5-4. 좌측 패널 별자리 애니메이션

- 별자리 점(circle)들 미세 twinkle: opacity 0.5↔1 (각각 다른 주기, 3-7초)
- 연결선(polyline) stroke-dasharray 느린 애니메이션
- 전체 별자리 미세 회전 (120초/1회전)

---

# Phase 6 — 커서 & 사운드

## 6-1. 커스텀 커서

- 기본: 12px 원형 (fg-paper border 1px, 투명 fill)
- 노드 위: 20px 동심원 (확대 전환, 0.2초)
- 인감 위: 사각 아웃라인 (인감 형태 미러링)
- 트레일: 커서 뒤 2-3개 ghost 잔상 (opacity 0.05-0.15, 30ms delay)
- CSS cursor: none + JS mousemove로 구현

## 6-2. Web Audio 앰비언트 (선택적)

- 사용자 첫 클릭 후 활성화 (autoplay 정책 준수)
- 저주파 드론: 180Hz sine, gain 0.02
- 노드 호버: 부드러운 톤 (각 노드별 다른 주파수, gain 0.05, 0.3초 decay)
- 인감 캡처: 공명 hit + reverb (0.8초)
- 음소거 토글: 우측 하단 스피커 아이콘
- 기본값: 음소거 상태 (사용자가 켜야 활성화)

---

# Phase 7 — 모바일 대응

## 7-1. 반응형 브레이크포인트

```
≤ 768px: 3-column → 단일 컬럼
≤ 480px: 모바일 최적화
```

## 7-2. 모바일 레이아웃

- 센터 패널만 기본 표시 (노드 + 인감)
- 좌/우 패널: 하단 탭 또는 스와이프로 전환
- 노드 배치: 좌/우 대신 상/하로 재배치 (화면 안에 수용)
- 인감 크기: 80px → 72px
- celestial nav: 상단 1줄 축약

## 7-3. 터치 최적화

- 노드 터치 영역: 60px → 최소 48px (이미 충족)
- 인감 터치 시: navigator.vibrate(50) (햅틱)
- 파티클 수: 80 → 30개로 감소 (성능)
- 커스텀 커서: 모바일에서 비활성화
- 입장 애니메이션: 2초로 단축

## 7-4. 프롤로그 히어로카드 모바일

- 카드 풀와이드 (20px 좌우 패딩)
- 일러스트 비율 유지, 높이 자동 조정
- 키워드 필: 가로 스크롤 또는 2행 wrap
- 스와이프로 다른 챕터 카드 전환
