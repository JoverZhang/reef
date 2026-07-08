from __future__ import annotations

from reef.core import derive_node_secret, load_model, render_subscriptions


def main() -> int:
    model = load_model()
    secret = bytes.fromhex(model.config.secret_hex)
    for node in model.nodes:
        derived = derive_node_secret(secret, node)
        if derived.fingerprint != model.secrets[node.id].fingerprint:
            raise RuntimeError(f"{node.id}: TLS certificate derivation is not deterministic")
    render_subscriptions(model)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
