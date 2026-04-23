# Phase 2 — 중앙 시각화

## 2-1. 노드 한문 → 영어/추상 전환

현재 8개 노드의 한문을 다음으로 교체:

| 현재 | 교체 옵션 A (영어 키워드) | 교체 옵션 B (추상 심볼) |
|------|--------------------------|------------------------|
| 氣 (기) | FLOW | 파동 아이콘 (~~~) |
| 靜 (정) | STILL | 수평선 아이콘 (—) |
| 空 (공) | VOID | 빈 원 아이콘 (○) |
| 明 (명) | LIGHT | 방사선 아이콘 (✦) |
| 心 (심) | CORE | 동심원 아이콘 (◎) |
| 道 (도) | PATH | 곡선 아이콘 (∿) |
| 理 (리) | ORDER | 그리드 아이콘 (⊞) |
| 法 (법) | FORM | 다면체 아이콘 (◇) |

추천: 옵션 B (추상 심볼) — 더 미니멀하고 언어 장벽 없음
노드 내부에 16-20px thin-line SVG 아이콘 배치
아래에 6px uppercase 라벨 (FLOW, STILL 등)

## 2-2. 인감(印) 버튼 → 영어 전환

현재 "印" → 다음 중 택 1:
- "SEAL" (직역, 간결)
- "CAPTURE" (행위 중심)
- 추상 심볼: ✦ 또는 ◉ (텍스트 없이 아이콘만)
- 추천: ◉ 심볼 + 하단에 "CAPTURE" 라벨

## 2-3. SVG 연결선 재설계

현재 div 1px 직선 → SVG path 곡선으로 전환:
- 노드 간 베지어 곡선 연결
- stroke-dasharray + stroke-dashoffset 애니메이션 → 에너지 흐름 느낌
- 연결선 위 미세 빛점 이동: SVG circle + animateMotion (8초 주기)
- 연결선 색상: line-ghost → 호버 시 fg-paper로 전환

## 2-4. 노드 비주얼 고도화

- 이중 링: 내부 실선 + 외부 점선(현재) + 세 번째 ghost ring (8% opacity, 90px)
- 각 노드별 다른 회전 속도 (15-30초) 및 방향 (CW/CCW 교차)
- 호버 시: 연결된 노드도 함께 반응 (연쇄 발광, 300ms delay)
- 노드 내부 아이콘에 text-shadow glow (호버 시 강화)

## 2-5. 중앙 축 (Talisman Axis) 개선

현재 단순 2px gradient 선 → 개선:
- SVG gradient line + 맥동 에너지 노드 3개 배치 (축 위 상/중/하)
- 에너지가 위→아래로 흐르는 animated gradient position (linear-gradient animation)
- 축 노드: 4px gold 원, 2초 주기 pulse
- 축 양 끝: 작은 기하학 터미널 장식 (삼각, 마름모)

## 2-6. MOMENTOR 타이틀

현재 유지하되:
- vertical writing-mode 유지
- text-shadow 강화: 2-layer glow (inner 10px + outer 40px)
- 미세한 letter-spacing 애니메이션 (hover 시 0.2em → 0.3em)
