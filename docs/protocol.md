## Message Format
All incoming and outgoing messages are structured as JSON objects with the following payload: 
"payload → ct in W4; no iv field, ever.
{
  "type": "msg",
  "seq": 42,
  "text": "Hello, server!", 
  "sender": "user"
  "timestamp" : <time>
}

## Field Definitions

| Field [2] | Type | Description |
|---|---|---|
| type | string | The purpose or command of the message  |
| seq | integer | A sequential identifier used to track message order and handle acknowledgments. |
| payload | string | The primary payload, content, or instruction associated with the message. |
| timestamp | datetime | Timestamp |


## Server End Points
/health
/status
/ws