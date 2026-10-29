# Notes

## How to run

Python 3.8 or newer, standard library only.

1. Copy `cloud-flare.sh` to `cloud-flare.local.sh` and fill in your Cloudflare account ID and a
   Workers AI API token. git ignores this file.
2. `python3 classify.py v1` labels `comments.json` with `clef-flash` and writes `results.html`.
   `python3 classify.py v2` labels `comments-v2.json` with `clef` and writes `results-v2.html`.
   Clef's raw answers go to `results.json` and `results-v2.json`.
3. Open the pages in a browser, or online:
   [results.html](https://kanav-midha.github.io/aiandi-intern/results.html),
   [results-v2.html](https://kanav-midha.github.io/aiandi-intern/results-v2.html).

Add `--html-only` to rebuild a page from the saved JSON without calling Cloudflare, for example
after editing a MISTAKES file.

## Results

| | `comments.json` | `comments-v2.json` |
| --- | --- | --- |
| Model and criteria | `clef-flash`, v1 | `clef`, v2 |
| Wrong, by my review | 3 of 100 ([MISTAKES.md](MISTAKES.md)) | 5 of 100 ([MISTAKES-v2.md](MISTAKES-v2.md)) |
| Wrong among low-confidence answers | 1 of the 24 below 0.35 | 4 of the 13 below 0.5 |

- All 3 of `clef-flash`'s mistakes let toxic comments through: an insult inside a complaint about
  grading, a claim that a whole group of students cheat, and a put-down softened with "lol" and
  "bro". The v2 criteria spell these cases out. Re-running `comments.json` with them, `clef`
  matched my labels on all 100, and `clef-flash` fixed 1 of the 3 without new mistakes.
- `clef`'s 5 mistakes on the harder set: three toxic comments let through (sarcasm, name-calling,
  and telling people where to find a classmate to confront her), a phishing post not caught as
  spam, and a student reporting someone else's stereotype, labelled toxic.
- For `clef`, low confidence was a useful signal: checking only its 13 least-confident answers
  would have caught 4 of its 5 mistakes. For `clef-flash` it was not: 2 of its 3 mistakes were
  above the flag.

What I would try next: say outright that asking for passwords or logins is spam; ask Clef a
second question, "is the author quoting or reporting someone else's words?", because it still
reacted to the reported stereotype; and send low-confidence answers to a human first.

## How it works

- One Clef request per comment: a `choice` between acceptable, toxic and spam, with the thread,
  forum and course as context. The author's name is not sent, so it can't sway the answer.
- The criteria are in `CRITERIA` at the top of `classify.py`. Before running on the task data they
  were tested on made-up edge cases: 12 for v1, 17 for v2.
- Rate limits and server errors are retried, and answers are saved as they arrive, so an
  interrupted run resumes without paying for the same requests twice.
- The pages show each comment with Clef's label, confidence and probabilities, with filters and a
  "least confident first" sort. Review mode, with Clef's answer hidden until you pick, is how I
  checked Clef and produced the MISTAKES files. Once those exist, the pages show my verdicts
  next to Clef's.

## Tools and models

- **Claude** (Anthropic), in the Claude app: researched the task and Clef, wrote `classify.py` and
  the pages, set up git, and helped turn my findings into the v2 criteria. Its commits are marked
  `Co-Authored-By: Claude`.
- **Cloudflare Workers AI**: `clef-flash` and `clef`.
- **The checking** in `MISTAKES.md` and `MISTAKES-v2.md` is mine: I read every comment and Clef's
  label myself, without AI.

## What I felt about doing this

<!-- KANAV: replace this line with 3–5 sentences in your own words. -->
