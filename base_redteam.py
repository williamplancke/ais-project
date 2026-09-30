import deepteam
import os
os.environ["DEEPEVAL_PER_ATTEMPT_TIMEOUT_SECONDS_OVERRIDE"] = "1200"

from deepeval import assert_test
from deepeval.test_case import LLMTestCase, SingleTurnParams
from deepeval.metrics import GEval, BiasMetric, PIILeakageMetric
from deepeval.models import OllamaModel
from ollama import Client
import pandas as pd
from deepteam import red_team
from deepteam.vulnerabilities import Bias, PromptLeakage, PIILeakage, GoalTheft, Robustness
from deepteam.attacks.single_turn import PromptInjection, Roleplay
def test_correctness(model, text_input, expected_output):
    if type(text_input) != list:
        list_text_input = [text_input]
    else:
        list_text_input = text_input
    if type(list_text_input[0]) != dict:
        list_text_input[0] = {
            "role": "user",
            "content": list_text_input[0]
        }
    dict_text_input = list_text_input
    actual_output = model.chat("deepseek-coder:1.3b-instruct-q4_K_S", messages=dict_text_input).message.content
    metric = GEval(
        model=get_ollama_model("deepseek-coder:1.3b-instruct-q4_K_S"),
        name="Correctness",
        evaluation_steps=[
            "Compare the actual output with the expected output.",
            "Identify factual errors and important omissions.",
            "Score correctness and completeness, and briefly explain the score.",
        ],
        evaluation_params=[SingleTurnParams.ACTUAL_OUTPUT, SingleTurnParams.EXPECTED_OUTPUT],
        threshold=0.5,
        async_mode=False
    )
    test_case = LLMTestCase(
        input=text_input,
        # Replace this with the actual output from your LLM application
        actual_output=actual_output,
        expected_output=expected_output
    )
    try:
        score = metric.measure(test_case)
    except:
        score = None
    return [text_input, expected_output, actual_output, score, metric.reason]
def get_ollama_model(name, temp=0):
    return OllamaModel(
        model=name,
        base_url="http://localhost:11434",
        temperature=temp
    )
def main(num_models: int = 1, vulnerability_extent: int = 0, attack_extent: int = 0):
    try:
        df_baseline = pd.read_csv("./llm_evaluation_baseline_results.csv", index_col=0)
        if df_baseline.shape[0] == 50:
            data_ready = True
        else:
            data_ready = False
    except:
        data_ready = False
    custom_llm = Client()
    if not data_ready:
        df_prompts = pd.read_csv("./llm_evaluation_prompts_with_outputs.csv", sep=";")
        results = []
        for _, row in df_prompts.iterrows():
            result = test_correctness(custom_llm, row["prompt"], row["output"])
            results.append(result)
        df_results = pd.DataFrame(results, columns=["Prompt", "Expected", "Actual", "Score", "Reason"])
        df_results.to_csv("llm_evaluation_baseline_results.csv")
        df_baseline = df_results
    bias = Bias()
    pii_leakage = PIILeakage()
    prompt_leakage = PromptLeakage()
    goal_theft = GoalTheft()
    robustness = Robustness()
    prompt_injection = PromptInjection()
    roleplay = Roleplay()
    models = ["maternion/ling-3.0-tiny:8b","qwen3:8b","llama3.1:8b","deepseek-coder:1.3b-instruct-q4_K_S"]
    assessments = []
    vuln = []
    att = []
    if num_models > len(models):
        continue
    else:
        models = models[0:num_models]
    vuln.append(prompt_leakage)
    att.append(prompt_injection)
    if vulnerability_extent > 0:
        vuln.append(pii_leakage)
        vuln.append(bias)
    if vulnerability_extend > 1:
        vuln.append(goal_theft)
        vuln.append(robustness)
    if attack_extent > 0:
        att.append(roleplay)
    for model in models:
        assessment = red_team(
            model_callback=get_ollama_model(model), # Change the model name to your desired model
            vulnerabilities=[vuln],
            attacks=[att],
            simulator_model=get_ollama_model("qwen2.5-14b-tutor:32k"),
            evaluation_model=get_ollama_model("qwen2.5-14b-tutor:32k"),
            ignore_errors=False,
            async_mode=False,
        )
        assessments.append(assessment)
    return assessments