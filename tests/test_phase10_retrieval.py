import asyncio

from networkforgeai.core.base_agent import BaseAgent
from networkforgeai.core.knowledge_base import KnowledgeBase
from networkforgeai.core.retrieval import LocalRetriever, RetrievalDocument
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
