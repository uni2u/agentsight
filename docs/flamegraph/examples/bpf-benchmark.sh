#!/bin/bash
# Generate flamegraphs for bpf-benchmark project
# This script demonstrates the iterative tagging workflow for agentpprof

set -e

AGENTPPROF="${AGENTPPROF:-agentpprof}"
PROJECT_ROOT="${PROJECT_ROOT:-$HOME/workspace/bpf-benchmark}"
OUTPUT_DIR="${OUTPUT_DIR:-$(dirname "$0")}"

# Tag rules developed through iterative refinement
TAG_RULES=(
  # Session rules
  --tag-rule 'session:paper=(?i)paper|arxiv|latex|论文'
  --tag-rule 'session:review=(?i)review|审核'
  --tag-rule 'session:cleanup=(?i)clean|docker|disk|空间'
  --tag-rule 'session:naming=(?i)kinsn|kprog|native|naming|名字'
  --tag-rule 'session:bench=(?i)native-sim|benchmark|tetr'

  # Prompt rules
  --tag-rule 'prompt:paper=(?i)paper|arxiv|latex|abstract|intro|section|写作|JIT|逻辑|翻译|主旨|TCB|kernel|benchmark|K2|Merlin|charact|atc|论文|开源'
  --tag-rule 'prompt:naming=(?i)kinsn|kprog|kfunc|kops|insn|NativeOps|名字|叫啥|换成|命名'
  --tag-rule 'prompt:review=(?i)review|审核|check|问题|diff|看看'
  --tag-rule 'prompt:git=(?i)commit|push|pull|git|submodule|patch|上游'
  --tag-rule 'prompt:cleanup=(?i)clean|ignore|docker|cache|disk|空间|REMOVING|磁盘|目录|用户|Volumes|Images|清理|GB'
  --tag-rule 'prompt:debug=(?i)fix|error|bug|broken'
  --tag-rule 'prompt:subagent=(?i)subagent|task-notification'
  --tag-rule 'prompt:format=(?i)格式|字体|图|style|format|idiom'
  --tag-rule 'prompt:edit=(?i)修|改|加|更新|减少|填|保持|不要'
  --tag-rule 'prompt:author=(?i)author|yusheng|zhengjie|contributor|标注|Hao Sun|ETH'
  --tag-rule 'prompt:confirm=(?i)^嗯$|^是$|^好$|我看不到'
  --tag-rule 'prompt:context=(?i)session is being continued'
  --tag-rule 'prompt:progress=(?i)进展|进度|如何了'
  --tag-rule 'prompt:discuss=(?i)觉得|是不是|会不会|有没有|还是|呢$|想想|效果|什么'
  --tag-rule 'prompt:continue=(?i)^继续$|讲解|分析一下'
  --tag-rule 'prompt:chat=(?i)不不不|你先|bpf ext'

  # LLM response rules (match model output patterns)
  --tag-rule 'llm:redacted=(?i)codex token report'
  --tag-rule 'llm:response=(?i)claude response'
  --tag-rule 'llm:paper=(?i)编译|tex|pdf|abstract|intro|section|段落|逻辑|翻译'
  --tag-rule 'llm:git=(?i)commit|push|submodule|remote'
  --tag-rule 'llm:edit=(?i)修改|修复|继续|处理|让我'
  --tag-rule 'llm:review=(?i)分析|检查|验证|问题|看|确认'
  --tag-rule 'llm:naming=(?i)kinsn|kprog|kfunc|kops|insn|命名'
)

echo "Generating flamegraphs for bpf-benchmark..."

for view in tokens files network time; do
  echo "  $view..."
  "$AGENTPPROF" \
    --project-root "$PROJECT_ROOT" \
    --project-name bpf-benchmark \
    "${TAG_RULES[@]}" \
    --view "$view" \
    -o "$OUTPUT_DIR/bpf-benchmark-${view}.svg"

  "$AGENTPPROF" \
    --project-root "$PROJECT_ROOT" \
    --project-name bpf-benchmark \
    "${TAG_RULES[@]}" \
    --view "$view" \
    -o "$OUTPUT_DIR/bpf-benchmark-${view}.folded"
done

echo "Done. Generated:"
ls -la "$OUTPUT_DIR"/bpf-benchmark-*.svg "$OUTPUT_DIR"/bpf-benchmark-*.folded 2>/dev/null || true
