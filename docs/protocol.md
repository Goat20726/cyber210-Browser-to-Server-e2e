## Message Format
All incoming and outgoing messages are structured as JSON objects with the following payload: 
{
  "type": "msg",
  "seq": 42,
  "text": "Hello, server!", 
  "sender": "user",
  "timestamp" : <time>
}
text → ct in W4; no iv field, ever.

## Field Definitions

| Field [2] | Type | Description |
|---|---|---|
| type | string | The purpose or command of the message  |
| seq | integer | A sequential identifier used to track message order and handle acknowledgments. |
| text | string | The primary payload, content, or instruction associated with the message. |
| sender | string | User or Assistant. |
| timestamp | datetime | Timestamp |


## Server End Points
/api/health
/api/status
/ws