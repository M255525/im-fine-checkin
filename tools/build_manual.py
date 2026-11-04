# 組合 manual.html：manual_body.html＋賞鳥地圖手冊裡的完整版創作者區塊（只在工作區本機跑）
import os, re
here = os.path.dirname(os.path.abspath(__file__))
src = os.path.join(here, '..', '..', '..', '互動遊戲', 'taiwan-bird-atlas', 'tools', 'manual_tpl.html')
tpl = open(src, encoding='utf-8').read()
i = tpl.index('<div class="mk-creator">')
depth = 0
for m in re.finditer(r'<div\b|</div>', tpl[i:]):
    depth += -1 if m.group() == '</div>' else 1
    if depth == 0:
        block = tpl[i:i + m.end()]
        break
body = open(os.path.join(here, 'manual_body.html'), encoding='utf-8').read()
open(os.path.join(here, '..', 'manual.html'), 'w', encoding='utf-8', newline='\n').write(body.replace('{{CREATOR}}', block))
print(len(block))
