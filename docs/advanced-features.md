# Advanced features

This page describes the first Phase 10 capability: local retrieval-augmented
context for model-backed agent analysis.

## What retrieval does

During a scan, agents can share discoveries through the orchestrator's
knowledge base. When an agent calls `analyze_context`, NetworkForgeAI searches
that shared knowledge for words related to the agent's question and appends the
best matches to the model prompt.

The initial implementation is deliberately modest and easy to audit:

- It is local and dependency-free. It does not call an embedding service,
  external search engine, or model to perform retrieval.
- Results are ranked by deterministic word overlap, so the same scan state and
  question produce the same ordering.
- The caller controls the knowledge-base contents. Retrieval does not discover
  new targets or execute tools.
- Fields whose names contain `credential`, `password`, `secret`, `token`, or
  `api_key` are excluded from retrieval context.
- Empty questions, zero/negative result limits, and unrelated knowledge return
  no matches.

## What retrieval does not do yet

The foundation also includes an optional hybrid retriever. Callers that already
have vectors can attach them to documents and provide a query vector; the
retriever combines cosine similarity with the deterministic lexical score. If
vectors are absent, it automatically falls back to local lexical retrieval.
NetworkForgeAI does not generate vectors or contact an embedding service yet.
Model output remains an untrusted recommendation, and every tool action still
follows the normal scope and approval controls.

## For developers

You can retrieve explicit documents directly:

```python
from networkforgeai.core.retrieval import LocalRetriever, RetrievalDocument

retriever = LocalRetriever(
    [RetrievalDocument("finding-1", "HTTPS is exposed on port 443")]
)
matches = retriever.search("HTTPS port")
```

For vector-aware callers, use `HybridRetriever` and provide matching vector
dimensions. A vector mismatch is treated as no semantic match rather than an
error, which keeps provider integration failures from bypassing the safe
lexical fallback.

Most agents should use `BaseAgent.analyze_context` instead. Agents registered
with `ScanOrchestrator` automatically receive its shared knowledge base.

## Few-shot examples

An agent can optionally provide a few trusted input/output examples. These
examples help a model follow the desired response shape without changing tool
permissions or approval rules:

```python
from networkforgeai.models.ai_capabilities import FewShotExample

agent = MyAgent(
    few_shot_examples=[
        FewShotExample(
            input_text="A service reports HTTPS on port 443.",
            output_text='{"type": "service", "value": "443/tcp", "confidence": "HIGH"}',
            label="recon discovery",
        )
    ]
)
```

Examples are opt-in and bounded to three examples and 4,000 characters per
analysis. Empty examples are ignored. They should contain sanitized, trusted
guidance only; they are not a way to pass secrets, authorize actions, or bypass
scope checks.

## Multi-agent debate

`MultiAgentDebate` can ask a bounded set of agents for independent opinions and
then request one peer-critique round. It returns the opinions and critiques for
human or application-level review; it does not select a winner, execute tools,
change the knowledge base, or grant approval.

```python
from networkforgeai.core.debate import MultiAgentDebate

result = await MultiAgentDebate(max_participants=3, max_rounds=2).run(
    "Assess the evidence for this finding", context, [recon_agent, scanner_agent]
)
```

The coordinator caps participation at three agents by default, caps discussion
at two rounds, and truncates each response before it is shared with peers.
Provider failures are recorded by type without exposing exception details.
