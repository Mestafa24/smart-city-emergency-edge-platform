import json
import re
import time
from typing import Dict, Any, List, Optional

from gateway_store import GatewayStore

COPILOT_PREFIX = "[COPILOT]"
WORD_NUMBERS = {
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
    "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
}

class CopilotEngine:
    def __init__(self, store: GatewayStore) -> None:
        self.store = store

    def envelope(
        self,
        *,
        event_id: int,
        kind: str,
        stage: str,
        text: str,
        choices: Optional[List[str]] = None,
        severity: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> str:
        # Keep choices for Android quick replies, but omit severity to save bytes
        # and to avoid the extra green "Priority" banner.
        obj: Dict[str, Any] = {
            "v": 1,
            "kind": kind,
            "stage": stage,
            "incident_id": event_id,
            "text": text,
        }
        if choices:
            obj["choices"] = choices
        if extra:
            obj.update(extra)

        max_bytes = 235
        encoded = COPILOT_PREFIX + json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) <= max_bytes:
            return encoded

        base_text = str(obj.get("text") or "")
        if not base_text:
            return encoded

        suffix = "..."
        trimmed = base_text
        while trimmed:
            trimmed = trimmed[:-1]
            obj["text"] = trimmed.rstrip() + suffix
            encoded = COPILOT_PREFIX + json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
            if len(encoded.encode("utf-8")) <= max_bytes:
                return encoded

        obj["text"] = suffix
        return COPILOT_PREFIX + json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

    def _now_ms(self) -> int:
        return int(time.time() * 1000)

    def start_for_event(self, event_id: int) -> List[str]:
        event = self.store.get_event(event_id)
        if not event:
            return []
        self.store.update_event_fields(
            event_id,
            incident_status="triage_active",
            copilot_stage="injury",
            last_gateway_message_ms=self._now_ms(),
        )
        text = (
            "SOS received. First question: what is your injury status?"
        )
        msg = self.envelope(
            event_id=event_id,
            kind="question",
            stage="injury",
            text=text,
            choices=["none", "mild", "severe"],
            severity=event.get("severity_level") or "unknown",
        )
        self.store.add_copilot_message(event_id=event_id, direction="gateway", kind="question", stage="injury", body=text, raw_json=self._try_json(msg))
        return [msg]

    def handle_reply(self, sender_peer: str, text: str) -> List[str]:
        event = self.store.get_active_event_for_sender(sender_peer)
        if not event:
            msg = self.envelope(
                event_id=0,
                kind="guidance",
                stage="idle",
                text="I do not see an active SOS incident for you. Send SOS first, then I can triage and guide you.",
            )
            return [msg]

        event_id = int(event["id"])
        stage = str(event.get("copilot_stage") or "injury")
        clean = text.strip()
        self.store.add_copilot_message(event_id=event_id, direction="victim", kind="reply", stage=stage, body=clean)
        self.store.update_event_fields(event_id, last_contact_ms=self._now_ms())

        if clean.lower() in {"help", "repeat", "again", "what"}:
            return [self._repeat_prompt(event)]

        if stage == "injury":
            return self._handle_injury(event, clean)
        if stage == "mobility":
            return self._handle_mobility(event, clean)
        if stage == "hazards":
            return self._handle_hazards(event, clean)
        if stage == "people":
            return self._handle_people(event, clean)
        return self._handle_triage_completed(event, clean)

    def _repeat_prompt(self, event: dict) -> str:
        stage = str(event.get("copilot_stage") or "injury")
        event_id = int(event["id"])
        severity = event.get("severity_level") or "unknown"
        if stage == "injury":
            text = "Please tell me your injury status."
            choices = ["none", "mild", "severe"]
        elif stage == "mobility":
            text = "Please tell me whether you are trapped, mobile, or unsure."
            choices = ["trapped", "mobile", "unsure"]
        elif stage == "hazards":
            text = "Please tell me the hazards you see."
            choices = ["fire", "smoke", "collapse", "flood", "gas", "none"]
        elif stage == "people":
            text = "How many people are with you, including you?"
            choices = ["1", "2", "3", "4+"]
        else:
            text = "Send updates like worse, better, trapped, mobile, smoke, or fire."
            choices = ["worse", "better", "trapped", "mobile", "smoke", "fire"]
        msg = self.envelope(event_id=event_id, kind="question", stage=stage, text=text, choices=choices, severity=severity)
        self.store.add_copilot_message(event_id=event_id, direction="gateway", kind="question", stage=stage, body=text, raw_json=self._try_json(msg))
        self.store.update_event_fields(event_id, last_gateway_message_ms=self._now_ms())
        return msg

    def _handle_injury(self, event: dict, text: str) -> List[str]:
        injury = self._parse_injury(text)
        event_id = int(event["id"])
        if not injury:
            return [self._clarify(event, "injury", "Reply with one word for injury status.", ["none", "mild", "severe"])]
        fields = {"injury_status": injury, "copilot_stage": "mobility", "incident_status": "triage_active"}
        self._apply_recalc(event_id, event, fields)
        response_text = f"I recorded injury status as {injury.upper()}. Next: are you trapped, mobile, or unsure?"
        msg = self.envelope(event_id=event_id, kind="question", stage="mobility", text=response_text, choices=["trapped", "mobile", "unsure"], severity=self.store.get_event(event_id)["severity_level"])
        self.store.add_copilot_message(event_id=event_id, direction="gateway", kind="question", stage="mobility", body=response_text, raw_json=self._try_json(msg))
        return [msg]

    def _handle_mobility(self, event: dict, text: str) -> List[str]:
        mobility = self._parse_mobility(text)
        event_id = int(event["id"])
        if not mobility:
            return [self._clarify(event, "mobility", "Reply with one word for mobility.", ["trapped", "mobile", "unsure"])]
        fields = {"mobility_status": mobility, "copilot_stage": "hazards"}
        self._apply_recalc(event_id, event, fields)
        response_text = "I recorded your mobility. Next: what hazards do you see around you?"
        msg = self.envelope(event_id=event_id, kind="question", stage="hazards", text=response_text, choices=["fire", "smoke", "collapse", "flood", "gas", "none"], severity=self.store.get_event(event_id)["severity_level"])
        self.store.add_copilot_message(event_id=event_id, direction="gateway", kind="question", stage="hazards", body=response_text, raw_json=self._try_json(msg))
        return [msg]

    def _handle_hazards(self, event: dict, text: str) -> List[str]:
        hazards = self._parse_hazards(text)
        event_id = int(event["id"])
        if hazards is None:
            return [self._clarify(event, "hazards", "Tell me the hazards you see.", ["fire", "smoke", "collapse", "flood", "gas", "none"])]
        fields = {"hazard_flags": json.dumps(hazards, ensure_ascii=False), "copilot_stage": "people"}
        self._apply_recalc(event_id, event, fields)
        response_text = "I recorded the hazards. Last triage question: how many people are with you, including you?"
        msg = self.envelope(event_id=event_id, kind="question", stage="people", text=response_text, choices=["1", "2", "3", "4+"], severity=self.store.get_event(event_id)["severity_level"])
        self.store.add_copilot_message(event_id=event_id, direction="gateway", kind="question", stage="people", body=response_text, raw_json=self._try_json(msg))
        return [msg]

    def _handle_people(self, event: dict, text: str) -> List[str]:
        count = self._parse_people_count(text)
        event_id = int(event["id"])
        if count is None:
            return [self._clarify(event, "people", "Reply with the number of people, including you.", ["1", "2", "3", "4+"])]
        fields = {"people_count": count, "copilot_stage": "triage_completed", "incident_status": "triage_completed"}
        new_event = self._apply_recalc(event_id, event, fields)
        summary = self._build_summary(new_event)
        guidance = self._build_guidance(new_event)
        self.store.update_event_fields(event_id, guidance_text=guidance, triage_summary=summary)

        confirm_text = self._build_victim_confirmation_text(new_event)
        guidance_text = self._build_victim_guidance_text(new_event)

        msgs: List[str] = []

        confirm_msg = self.envelope(
            event_id=event_id,
            kind="summary",
            stage="triage_completed",
            text=confirm_text,
            severity=new_event["severity_level"],
        )
        self.store.add_copilot_message(
            event_id=event_id,
            direction="gateway",
            kind="summary",
            stage="triage_completed",
            body=confirm_text,
            raw_json=self._try_json(confirm_msg),
        )
        msgs.append(confirm_msg)

        guidance_msg = self.envelope(
            event_id=event_id,
            kind="guidance",
            stage="triage_completed",
            text=guidance_text,
            severity=new_event["severity_level"],
        )
        self.store.add_copilot_message(
            event_id=event_id,
            direction="gateway",
            kind="guidance",
            stage="triage_completed",
            body=guidance_text,
            raw_json=self._try_json(guidance_msg),
        )
        msgs.append(guidance_msg)

        self.store.update_event_fields(event_id, last_gateway_message_ms=self._now_ms())
        return msgs

    def _handle_triage_completed(self, event: dict, text: str) -> List[str]:
        event_id = int(event["id"])
        text_l = text.lower()
        updates: Dict[str, Any] = {}
        injury = self._parse_injury(text)
        mobility = self._parse_mobility(text)
        hazards = self._parse_hazards(text)
        if "worse" in text_l:
            injury = "severe"
        elif "better" in text_l and event.get("injury_status") == "severe":
            injury = "mild"
        if injury:
            updates["injury_status"] = injury
        if mobility:
            updates["mobility_status"] = mobility
        if hazards is not None:
            updates["hazard_flags"] = json.dumps(hazards, ensure_ascii=False)
        if not updates:
            msg = self.envelope(event_id=event_id, kind="guidance", stage="triage_completed", text="Update received. I can record changes like worse / better / trapped / mobile / fire / smoke / collapse / flood.", choices=["worse", "better", "trapped", "mobile", "smoke", "fire"], severity=event.get("severity_level") or "unknown")
            self.store.add_copilot_message(event_id=event_id, direction="gateway", kind="guidance", stage="triage_completed", body="Update received. I can record changes like worse / better / trapped / mobile / fire / smoke / collapse / flood.", raw_json=self._try_json(msg))
            return [msg]
        new_event = self._apply_recalc(event_id, event, updates)
        summary = self._build_summary(new_event)
        self.store.update_event_fields(event_id, triage_summary=summary)
        msg_text = f"Update recorded. {summary}"
        msg = self.envelope(event_id=event_id, kind="summary", stage="triage_completed", text=msg_text, severity=new_event["severity_level"])
        self.store.add_copilot_message(event_id=event_id, direction="gateway", kind="summary", stage="triage_completed", body=msg_text, raw_json=self._try_json(msg))
        return [msg]

    def _clarify(self, event: dict, stage: str, text: str, choices: List[str]) -> str:
        event_id = int(event["id"])
        msg = self.envelope(event_id=event_id, kind="question", stage=stage, text=text, choices=choices, severity=event.get("severity_level") or "unknown")
        self.store.add_copilot_message(event_id=event_id, direction="gateway", kind="question", stage=stage, body=text, raw_json=self._try_json(msg))
        self.store.update_event_fields(event_id, last_gateway_message_ms=self._now_ms())
        return msg

    def _apply_recalc(self, event_id: int, event: dict, updates: Dict[str, Any]) -> dict:
        merged = dict(event)
        merged.update(updates)
        score = self._severity_score(merged)
        level = self._severity_level(score)
        updates = dict(updates)
        updates["severity_score"] = score
        updates["severity_level"] = level
        updates["last_gateway_message_ms"] = self._now_ms()
        self.store.update_event_fields(event_id, **updates)
        return self.store.get_event(event_id) or merged

    def _severity_score(self, event: dict) -> int:
        score = 0
        injury = event.get("injury_status")
        if injury == "severe":
            score += 4
        elif injury == "mild":
            score += 2
        mobility = event.get("mobility_status")
        if mobility == "trapped":
            score += 4
        elif mobility == "unsure":
            score += 2
        elif mobility == "mobile":
            score += 1
        hazards = event.get("hazard_flags") or []
        if isinstance(hazards, str):
            try:
                hazards = json.loads(hazards)
            except Exception:
                hazards = [h.strip() for h in hazards.split(",") if h.strip()]
        weights = {"fire": 3, "smoke": 2, "collapse": 4, "flood": 2, "gas": 3}
        for h in hazards:
            score += weights.get(str(h).lower(), 0)
        people = event.get("people_count")
        try:
            if people is not None and int(people) > 1:
                score += 1
        except Exception:
            pass
        acc = event.get("acc")
        try:
            if acc is not None and float(acc) > 50:
                score += 1
        except Exception:
            pass
        return int(score)

    def _severity_level(self, score: int) -> str:
        if score >= 9:
            return "critical"
        if score >= 6:
            return "high"
        if score >= 3:
            return "medium"
        if score >= 0:
            return "low"
        return "unknown"

    def _build_summary(self, event: dict) -> str:
        hazards = event.get("hazard_flags") or []
        if isinstance(hazards, str):
            try:
                hazards = json.loads(hazards)
            except Exception:
                hazards = [hazards]
        hazard_text = ", ".join(hazards) if hazards else "none"
        people = event.get("people_count") or "unknown"
        return (
            f"Responder summary: severity {str(event.get('severity_level') or 'unknown').upper()}, "
            f"injury {str(event.get('injury_status') or 'unknown').upper()}, "
            f"mobility {str(event.get('mobility_status') or 'unknown').upper()}, "
            f"hazards {hazard_text.upper()}, people {people}."
        )
    
    def _build_guidance(self, event: dict) -> str:
        parts: List[str] = []
        hazards = event.get("hazard_flags") or []
        if isinstance(hazards, str):
            try:
                hazards = json.loads(hazards)
            except Exception:
                hazards = [hazards]
        if event.get("mobility_status") == "trapped":
            parts.append("If unsafe, stay where you are and make noise signals.")
        elif event.get("mobility_status") == "mobile":
            parts.append("If safe, move to a more visible and safer location.")
        else:
            parts.append("Do not move if you suspect injury.")
        if "smoke" in hazards:
            parts.append("Stay low under smoke.")
        if "fire" in hazards:
            parts.append("Avoid flames, and hot objects.")
        if "collapse" in hazards:
            parts.append("Protect your head from debris.")
        if "flood" in hazards:
            parts.append("Move to higher ground if safe.")
        if "gas" in hazards:
            parts.append("Avoid sparks or flames.")
        if event.get("injury_status") == "severe":
            parts.append("Press bleeding if safe.")
        parts.append("Conserve battery and keep your phone ready.")
        return " ".join(parts)
        
    def _build_victim_confirmation_text(self, event: dict) -> str:
        summary = self._build_summary(event)
        return f"Triage status: complete.\n{summary}"

    def _build_victim_guidance_text(self, event: dict) -> str:
        # Send the same compound, choice-dependent guidance that we compute for
        # responder-side storage, so the victim-facing message truly reflects
        # injury / mobility / hazards selections.
        return self._build_guidance(event)


    def _build_victim_completion_text(self, event: dict) -> str:
        """Compact final message that stays under BitChat's 255-byte TLV field limit."""
        hazards = event.get("hazard_flags") or []
        if isinstance(hazards, str):
            try:
                hazards = json.loads(hazards)
            except Exception:
                hazards = [hazards]
        hazard_text = ", ".join(str(h).upper() for h in hazards) if hazards else "NONE"
        people = event.get("people_count") or "?"
        severity = str(event.get("severity_level") or "unknown").upper()
        injury = str(event.get("injury_status") or "unknown").upper()
        mobility = str(event.get("mobility_status") or "unknown").upper()

        parts = [
            f"Triage complete. Injury {injury}; mobility {mobility}; hazards {hazard_text}; people {people}.",
        ]
        if mobility == "TRAPPED":
            parts.append("If unsafe to move, stay where you are.")
        elif mobility == "MOBILE":
            parts.append("If safe, move away from danger.")
        else:
            parts.append("Do not move if you suspect serious injury.")
        if "smoke" in [str(h).lower() for h in hazards]:
            parts.append("Stay low under smoke and cover mouth/nose.")
        if injury == "SEVERE":
            parts.append("Apply pressure to bleeding if safe.")
        parts.append("Conserve battery and keep phone ready.")

        text = " ".join(parts)
        if len(text.encode("utf-8")) > 240:
            # Hard fallback to ensure we never trip the TLV <=255 rule again.
            text = (
                f"Triage complete. Injury {injury}; mobility {mobility}; "
                f"hazards {hazard_text}; people {people}. Conserve battery and keep phone ready."
            )
        return text

    def _parse_injury(self, text: str) -> Optional[str]:
        t = text.lower()
        if any(w in t for w in ["severe", "critical", "badly", "bleed", "blood", "broken", "unconscious"]):
            return "severe"
        if any(w in t for w in ["mild", "minor", "small", "bruise", "cut"]):
            return "mild"
        if t in {"none", "no"} or "not injured" in t or "no injury" in t or "okay" in t:
            return "none"
        return None

    def _parse_mobility(self, text: str) -> Optional[str]:
        t = text.lower()
        if any(w in t for w in ["trapped", "stuck", "cant move", "can't move", "pinned"]):
            return "trapped"
        if any(w in t for w in ["mobile", "can move", "walking", "walk", "moving"]):
            return "mobile"
        if "unsure" in t or "not sure" in t or "don't know" in t:
            return "unsure"
        return None

    def _parse_hazards(self, text: str) -> Optional[List[str]]:
        t = text.lower()
        hazards: List[str] = []
        for key in ["fire", "smoke", "collapse", "flood", "gas"]:
            if key in t:
                hazards.append(key)
        if "none" in t or "no hazard" in t or "clear" in t:
            return []
        if hazards:
            # preserve order, remove duplicates
            seen = set()
            out = []
            for h in hazards:
                if h not in seen:
                    out.append(h)
                    seen.add(h)
            return out
        return None

    def _parse_people_count(self, text: str) -> Optional[int]:
        t = text.strip().lower()
        if t in {"alone", "just me", "me only"}:
            return 1
        m = re.search(r"\b(\d{1,2})\b", t)
        if m:
            return int(m.group(1))
        for word, num in WORD_NUMBERS.items():
            if re.search(rf"\b{word}\b", t):
                return num
        if "4+" in t or "many" in t:
            return 4
        return None

    def _try_json(self, content: str) -> Optional[Dict[str, Any]]:
        if not content.startswith(COPILOT_PREFIX):
            return None
        try:
            return json.loads(content[len(COPILOT_PREFIX):])
        except Exception:
            return None
