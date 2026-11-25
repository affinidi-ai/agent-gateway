"""pytest plugin the harness loads into the A2A 0.3 TCK.

The 0.3 TCK looks for the agent card at the root of the host it is given,
whatever path the agent is served under. A gateway surface is served under a
path, and so is its card, so the TCK would find no card and run nothing. This
plugin makes it look under the URL it was given, as the 1.0 TCK does.
"""

import requests

import tck.agent_card_utils

CARD_PATHS = ('/.well-known/agent-card.json', '/.well-known/agent.json')


def fetch_agent_card(sut_base_url: str, session: requests.Session) -> dict | None:
    for path in CARD_PATHS:
        try:
            response = session.get(f'{sut_base_url.rstrip("/")}{path}', timeout=10)
            response.raise_for_status()
            card = response.json()
        except (requests.RequestException, ValueError):
            continue
        if isinstance(card, dict):
            return card
    return None


tck.agent_card_utils.fetch_agent_card = fetch_agent_card
