#!/bin/bash
# Generate flamegraphs for bpf-benchmark project
# This script demonstrates the iterative tagging workflow for agentpprof

set -e

AGENTPPROF="${AGENTPPROF:-agentpprof}"
PROJECT_ROOT="${PROJECT_ROOT:-$HOME/workspace/bpf-benchmark}"
OUTPUT_DIR="${OUTPUT_DIR:-$(dirname "$0")}"

# Tag rules developed through iterative refinement
# Coverage: 100% (70/70 prompts matched)
TAG_RULES=(
  # Paper writing: LaTeX, arxiv, sections, logic discussions
  --tag-rule 'prompt:paper=(?i)paper|arxiv|latex|abstract|intro|section|写作|JIT|逻辑|翻译|主旨|TCB|kernel|benchmark|K2|Merlin|charact'

  # Review: checking, auditing, examining
  --tag-rule 'prompt:review=(?i)review|审核|check|问题|diff|看看'

  # Git operations
  --tag-rule 'prompt:git=(?i)commit|push|pull|git|submodule'

  # Cleanup: disk space, docker, caches
  --tag-rule 'prompt:cleanup=(?i)clean|ignore|docker|cache|disk|空间|REMOVING|磁盘|目录|用户'

  # Debugging
  --tag-rule 'prompt:debug=(?i)fix|error|bug|broken'

  # Subagent notifications
  --tag-rule 'prompt:subagent=(?i)subagent|task-notification'

  # Formatting: style, figures, fonts
  --tag-rule 'prompt:format=(?i)格式|字体|图|style|format|idiom'

  # Editing: modifications, additions, updates
  --tag-rule 'prompt:edit=(?i)修|改|加|更新|减少|填|保持|不要'

  # Author metadata
  --tag-rule 'prompt:author=(?i)author|yusheng|zhengjie|contributor|标注|Hao Sun|ETH'

  # Confirmations
  --tag-rule 'prompt:confirm=(?i)^嗯$|^是$|^好$|我看不到'

  # Context continuations
  --tag-rule 'prompt:context=(?i)session is being continued'
)

echo "Generating flamegraphs for bpf-benchmark..."

for view in tokens files network; do
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
