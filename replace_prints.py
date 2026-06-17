import os
import re

path = 'bas_engine/attack_modules/ssh_bruteforce.py'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Replace print( with await self.emit_event('INFO', 
new_content = re.sub(r'\bprint\s*\(', "await self.emit_event('INFO', ", content)

with open(path, 'w', encoding='utf-8') as f:
    f.write(new_content)

print('Success')
