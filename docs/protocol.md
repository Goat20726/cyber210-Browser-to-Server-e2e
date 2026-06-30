## Message Format
All incoming and outgoing messages are structured as JSON objects with the following payload: 
```
{
  "type": "msg",
  "seq": 42,
  "text": "Hello, server!", 
  "sender": "user",
  "timestamp" : <time>
}
```
text → ct in W4; no iv field, ever.

## Field Definitions

| Field  | Type | Description |
|---|---|---|
| type | string | The purpose or command of the message  |
| seq | integer | A sequential identifier used to track message order and handle acknowledgments. |
| text | string | The primary payload, content, or instruction associated with the message. |
| sender | string | User or Assistant. |
| timestamp | datetime | Timestamp |

## HKPE
Salt = 65b9295c885b667d3ce7d06afaee50edabb816af6f3b64a763d6b75201e6ed95
info_x25519 = echovault-x25519-encryption
info_ed25519 = echovault-ed25519-signing
### WebCrypto using raw scalar



## Server End Points
/api/health
/api/status
/ws