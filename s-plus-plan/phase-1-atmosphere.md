# Phase 1 — 배경 & 분위기

## 1-1. Canvas 파티클 시스템

- ink blob 뒤에 전체 화면 canvas 레이어 추가
- 부유 입자 50-80개: fg-paper 색, 0.3-1px, opacity 0.1-0.4
- 마우스 위치에 따라 약하게 밀려나는 반응 (repulsion radius 100px)
- 느린 브라운 운동 (random drift), 프레임당 0.1-0.3px 이동
- 성능: requestAnimationFrame, 모바일에서는 입자 30개로 감소

## 1-2. 잉크 워시 고도화

- 현재 3개 blob → SVG feTurbulence 필터 적용으로 유기적 형태
- 각 blob 독립 drift + scale + rotation 복합 애니메이션 (25-35초 주기)
- 4번째 blob 추가: 인감 뒤 cinnabar 은은한 빛 (rgba(181,41,27,0.08))
- blob 간 색상 미세 변화: 시간대에 따라 새벽=청조, 낮=중립, 밤=자색

## 1-3. 학 SVG 교체

- 현재 단순 path 4개 → 더 정교한 필묘(筆描) 스타일로 교체
- path 포인트 2배 이상 증가 → 날개깃, 다리, 목 디테일
- 날갯짓 미세 애니메이션: path morphing으로 3% 이동 (8초 주기)
- opacity breathing: 0.2 ↔ 0.5 (10초 주기)
- 또는 학 대신 Co-Star 스타일의 에칭 일러스트로 교체 가능:
  천문 의기(혼천의), 나침반, 또는 추상 celestial map

## 1-4. 그레인 텍스처 (Phase 0과 연결)

- SVG filter: feTurbulence(baseFrequency 0.65, numOctaves 4)
- 전체 화면 오버레이, pointer-events: none
- opacity 0.03-0.05, mix-blend-mode: overlay
- 화선지/필름 느낌 → 디지털 차가움 제거
