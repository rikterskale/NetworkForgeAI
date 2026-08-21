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

This foundation is not semantic search. It does not understand synonyms,
generate embeddings, ingest external threat-intelligence feeds, or replace
human approval. Model output remains an untrusted recommendation, and every
tool action still follows the normal scope and approval controls.

## For developers

You can retrieve explicit documents directly:

```python
from networkforgeai.core.retrieval import LocalRetriever, RetrievalDocument

retriever = LocalRetriever(
    [RetrievalDocument("finding-1", "HTTPS is exposed on port 443")]
)
matches = retriever.search("HTTPS port")
```

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
