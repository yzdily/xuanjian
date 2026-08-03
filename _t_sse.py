import sys
sys.path.insert(0, '.')
from core.llm import _parse_sse_chat_payload

sse = ': keep-alive connection established\n\n' \
      'data: {"id":"x","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":"think1","content":"Hello "},"finish_reason":null}]}\n\n' \
      'data: {"id":"x","choices":[{"index":0,"delta":{"content":"world"},"finish_reason":null}]}\n\n' \
      'data: {"id":"x","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}\n\n' \
      'data: [DONE]\n'

r = _parse_sse_chat_payload(sse)
print('content=', repr(r.choices[0].message.content))
print('reasoning=', repr(r.choices[0].message.reasoning_content))
print('tool_calls=', r.choices[0].message.tool_calls)
print('finish=', r.choices[0].finish_reason)
print('usage=', r.usage.prompt_tokens, r.usage.completion_tokens)

sse2 = 'data: {"id":"c","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_","arguments":"{\\\"a\\\"}"}}]},"finish_reason":null}]}\n' \
       'data: {"id":"c","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"time","arguments":":1"}}]},"finish_reason":null}]}\n'
r2 = _parse_sse_chat_payload(sse2)
tc = r2.choices[0].message.tool_calls[0]
print('tool name=', tc.function.name, 'args=', tc.function.arguments, 'id=', tc.id)

print('nonstr passthrough ok:', _parse_sse_chat_payload({'a':1}) == {'a':1})
print('empty str ok:', _parse_sse_chat_payload(''))