# Playbook: <Rule title>

| Field | Value |
|---|---|
| Rule | [`<file>.yml`](../rules/...) |
| MITRE ATT&CK | TXXXX.XXX (<name>) |
| Severity | <Low / Medium / High> |
| Log source | <Sysmon EID X / Security 4XXX / ...> |

## 1. What this alert means

Two or three sentences on what happened and why it matters.

## 2. Triage (first 5-10 minutes)

1. First thing to check and why.
2. Parent process / user / host.
3. Specific indicators that separate malicious from legitimate.
4. Related activity before and after.

## 3. Common false positives

- Legitimate case 1 and how to recognize it.
- Legitimate case 2 and how to recognize it.

**How to confirm:** ...

## 4. Decision

| Situation | Action |
|---|---|
| ... | Close as false positive |
| ... | Check with the asset owner |
| ... | **Escalate** |

## 5. Information to include when escalating

- Minimum data the next tier needs.

## 6. References

- [MITRE ATT&CK TXXXX](https://attack.mitre.org/techniques/TXXXX/)