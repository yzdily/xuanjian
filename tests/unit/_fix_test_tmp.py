import re

p = r"f:\xuanjian-main\tests\unit\test_checks_supplement.py"
s = open(p, encoding="utf-8").read()
s2 = re.sub(r"body='[^']*'", 'body=\'{"query":"{user{id}}"}\'', s)
open(p, "w", encoding="utf-8").write(s2)
print("fixed, body occurrences:", s2.count('{user{id}}'))
