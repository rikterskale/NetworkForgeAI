import asyncio

from networkforgeai.core.base_agent import BaseAgent
from networkforgeai.core.debate import MultiAgentDebate
from networkforgeai.core.knowledge_base import KnowledgeBase
from networkforgeai.core.retrieval import HybridRetriever, LocalRetriever, RetrievalDocument
from networkforgeai.models.ai_capabilities import FewShotExample, format_few_shot_examples
from networkforgeai.models.base_adapter import Message


class RetrievalAgent(BaseAgent):
    async def execute(self, task, context):
        return {}

    def get_capabilities(self):
        return ["retrieval"]


class RecordingAdapter:
    def __init__(self):
        self.messages = []

    async def chat_with_retry(self, messages):
        self.messages = messages
        return messages[-1].content


def test_local_retriever_is_ranked_stable_and_bounded():
    retriever = LocalRetriever(
        [
            RetrievalDocument("b", "The web server exposes HTTP and HTTPS."),
            RetrievalDocument("a", "HTTPS is served by the web application."),
            RetrievalDocument("empty", ""),
        ]
    )
    results = retriever.search("web HTTPS", top_k=1)
    assert len(results) == 1
    assert results[0].document.document_id == "a"
    assert results[0].score == 1.0


def test_hybrid_retriever_uses_vectors_and_falls_back_safely():
    retriever = HybridRetriever(
        [
            RetrievalDocument("lexical", "database migration", embedding=(1.0, 0.0)),
            RetrievalDocument("semantic", "storage change", embedding=(0.0, 1.0)),
        ]
    )

    semantic_results = retriever.search(
        "unrelated wording", query_embedding=(0.0, 1.0), lexical_weight=0, semantic_weight=1
    )
    fallback_results = retriever.search("database", query_embedding=(1.0,))

    assert semantic_results[0].document.document_id == "semantic"
    assert fallback_results[0].document.document_id == "lexical"


def test_knowledge_base_retrieval_skips_secret_fields():
    async def scenario():
        knowledge = KnowledgeBase()
        await knowledge.update({"services": ["HTTPS on 443"], "api_token": "HTTPS admin token"})
        results = await knowledge.retrieve("HTTPS", top_k=5)
        assert [result.document.document_id for result in results] == ["services"]

    asyncio.run(scenario())


def test_agent_analysis_includes_retrieved_knowledge():
    async def scenario():
        knowledge = KnowledgeBase()
        await knowledge.set("services", ["HTTPS on port 443"])
        adapter = RecordingAdapter()
        agent = RetrievalAgent(model_adapter=adapter, knowledge_base=knowledge)
        response = await agent.analyze_context("Which services use HTTPS?", {})
        assert isinstance(response, str)
        assert "Retrieved knowledge:" in adapter.messages[-1].content
        assert "HTTPS on port 443" in adapter.messages[-1].content
        assert isinstance(adapter.messages[-1], Message)

    asyncio.run(scenario())


def test_few_shot_examples_are_bounded_and_formatted():
    examples = [
        FewShotExample("question", "answer", "demo"),
        FewShotExample("", "ignored"),
        FewShotExample("second", "response"),
        FewShotExample("third", "not included"),
    ]

    formatted = format_few_shot_examples(examples, max_examples=3, max_chars=200)

    assert "Example 1 (demo):" in formatted
    assert "question" in formatted
    assert "ignored" not in formatted
    assert "not included" not in formatted


def test_agent_analysis_includes_opt_in_few_shot_examples():
    async def scenario():
        adapter = RecordingAdapter()
        agent = RetrievalAgent(
            model_adapter=adapter,
            few_shot_examples=[FewShotExample("input", "output", "test")],
        )

        await agent.analyze_context("Analyze this", {})

        assert "Few-shot examples:" in adapter.messages[-1].content
        assert "Input: input" in adapter.messages[-1].content
        assert "Output: output" in adapter.messages[-1].content

    asyncio.run(scenario())


class DebateAgent:
    def __init__(self, participant_id, response):
        self.id = participant_id
        self.response = response
        self.prompts = []

    async def analyze_context(self, prompt, context):
        self.prompts.append((prompt, context))
        return self.response


def test_multi_agent_debate_is_bounded_and_advisory():
    async def scenario():
        agents = [
            DebateAgent("a", "opinion-a"),
            DebateAgent("b", "opinion-b"),
            DebateAgent("c", "ignored"),
        ]
        context = {"scope": ["example.com"]}
        result = await MultiAgentDebate(max_participants=2, max_chars=100).run(
            "Assess the evidence", context, agents, rounds=2
        )

        assert [opinion.participant_id for opinion in result.opinions] == ["a", "b"]
        assert len(result.critiques) == 2
        assert all("opinion-a" in agent.prompts[1][0] for agent in agents[:2])
        assert context == {"scope": ["example.com"]}
        assert agents[2].prompts == []

    asyncio.run(scenario())


def test_multi_agent_debate_records_provider_errors_without_authorizing_actions():
    async def scenario():
        failed = DebateAgent("failed", "unused")

        async def raise_error(prompt, context):
            raise RuntimeError("provider detail must not be exposed")

        failed.analyze_context = raise_error
        result = await MultiAgentDebate(max_rounds=1).run("Assess", {}, [failed])

        assert len(result.errors) == 1
        assert result.errors[0].error == "RuntimeError"
        assert result.errors[0].content == ""

    asyncio.run(scenario())
