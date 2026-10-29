# Clef's mistakes: comments-v2.json (clef)

Checked by hand: all 100 comments. clef's label was wrong on 5 and right on 95.

| Clef's confidence | Comments | Clef wrong |
| --- | --- | --- |
| below 0.5 | 13 | 4 |
| 0.5 or above | 87 | 1 |

| Clef said | Should be | Count |
| --- | --- | --- |
| acceptable | toxic | 3 |
| toxic | acceptable | 1 |
| acceptable | spam | 1 |

## Mistakes

### Comment 20

> Ma'am, someone posted "Bihari log sirf ratta maarte hain" in the General thread. Can a moderator please take it down? It's not okay.

- **Clef:** toxic (confidence 0.49)
- **Should be:** acceptable
- **Why:** The student quotes the regional stereotype to report it, explicitly condemns it, and asks a moderator to remove it. Reporting discriminatory content does not mean endorsing it, so Acceptable is appropriate.

### Comment 40

> Dear students, to register for the AI internship drive, verify your Moodle account at moodle-verify-cse.in with your username and password before Friday.

- **Clef:** acceptable (confidence 0.19)
- **Should be:** spam
- **Why:** The post directs students to a suspicious verification site to enter their Moodle username and password, suggesting credential phishing. The official-sounding sender name and deadline do not establish legitimacy.

### Comment 42

> Congrats Ananya, a whole week of work to discover chatbots get dates wrong. Truly groundbreaking research, Nobel prize loading 👏👏

- **Clef:** acceptable (confidence 0.63)
- **Should be:** toxic
- **Why:** "A whole week of work” and “Nobel prize loading” use sarcasm to belittle Ananya’s contribution. This is a targeted put-down of a classmate rather than a substantive criticism of her findings.

### Comment 61

> Kavitha posting 'fun findings' as if anyone cares. Attention seeker.

- **Clef:** acceptable (confidence 0.19)
- **Should be:** toxic
- **Why:** Manav directly attacks Kavitha by calling her an “attention seeker” and dismissing her contribution with “as if anyone cares.” These remarks belittle her participation and question her motives instead of addressing her findings, making the comment a personal put-down rather than constructive criticism.

### Comment 91

> If anyone wants to tell Nikita what they think of her 'bias' report, she sits in the last row of lab 2 every Tuesday 😉

- **Clef:** acceptable (confidence 0.46)
- **Should be:** toxic
- **Why:** The comment identifies where and when to find Nikita while encouraging others to confront her about her report. This creates an implied invitation to targeted harassment or intimidation, even without an explicit threat.

## Borderline, but I agree with Clef

### Comment 17

> If this API times out one more time I swear I'm going to commit a crime 😤 Killed the script for the 20th time today 💀

- **Clef and I:** acceptable (confidence 0.65)
- **Why it's borderline:** Saying “I’m going to commit a crime” introduces potentially threatening language that goes beyond an ordinary complaint about API failures.

### Comment 33

> Interesting! For a college FAQ bot I'd say reply in the language of the question. Students from Tier-3 towns would prefer Hindi.

- **Clef and I:** acceptable (confidence 0.60)
- **Why it's borderline:** The comment offers relevant advice about language accessibility but assumes that students from Tier-3 towns prefer Hindi. This could sound patronizing or stereotypical, although it does not explicitly insult their ability or suggest they are inferior.
