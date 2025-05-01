import json
import os
import random

from fastapi import FastAPI, Request, HTTPException
from openai import AsyncOpenAI
from py_solidity_vuln_db import get_vulnerability
from solc_ast_parser.utils import compile_contract_with_standart_input
from ai_audits.solidity_generator import SolidityGenerator
from openai import OpenAI
from ai_audits.contracts.contract_generator import (
    Vulnerability,
    create_contract,
    create_task,
)
from ai_audits.protocol import (
    SmartContract,
    ValidatorTask,
    KnownVulnerability,
    TaskType,
)
from ai_audits.subnet_utils import ROLES, SolcSingleton
from dotenv import load_dotenv

load_dotenv(override=True)
GPT_MODEL = "gpt-4o-mini"

client = OpenAI(
    base_url=os.getenv("OPENAI_API_URL"),
    api_key=os.getenv("OPENAI_API_KEY"),
)
app = FastAPI()


VULNERABILITIES_TO_GENERATE = [
    KnownVulnerability.SIGNATURE_REPLAY.value,
    KnownVulnerability.GAS_GRIEFING.value,
    KnownVulnerability.BAD_RANDOMNESS.value,
    KnownVulnerability.FORCED_RECEPTION.value,
    KnownVulnerability.UNGUARDED_FUNCTION.value,
    KnownVulnerability.REENTRANCY.value,
]


PROMPT_VALIDATOR = """
You are a Solidity smart contract auditor. 
Your role is to help user auditors learn about Solidity vulnerabilities by providing them with vulnerable contracts.
Be creative when generating contracts, avoid using common names or known contract structures. 
Do not include comments describing the vulnerabilities in the code, human auditors should identify them on their own.

Aim to create more complex contracts rather than simple, typical examples. 
Each contract should include 3-5 state variables and 3-5 functions, with at least one function MUST containing a vulnerability. 
Ensure that the contract code is valid and can be successfully compiled.

Generate response in text with no extra comments or explanations.

Output format:
<code>
""".strip()

PROMPT_VALID_CONTRACT = """
    You are a Solidity smart contract writer. 
    Your role is to help user writers learn Solidity smart contracts by providing them different examples of contracts.
    Be creative when generating contracts, avoid using common names or known contract structures. 
    Do not use primitive examples of contracts, human writers need to understand the complexity of the contracts.

    Aim to create more complex contracts rather than simple, typical examples.  
    You should add 5-7 state variables and 5-7 functions.
    Ensure that the contract code is valid and can be successfully compiled by solidity compiler.

    Generate response in text with no extra comments or explanations.
    Output format:
    <code>
"""


def get_hybrid_validator_prompt(code: str) -> str:
    return f"""
    You are a Solidity smart contract writer. 
    Your role is to help user writers learn Solidity smart contracts by providing them different examples of contracts.
    Be creative when generating contracts, avoid using common names or known contract structures. 
    Do not use primitive examples of contracts, human writers need to understand the complexity of the contracts.

    Aim to create more complex contracts rather than simple, typical examples. 
    You need to analyze this code: {code}
    and define or initialize all identifiers that are presented in this code, 
    except builtin functions and storages. (note: you are not allowed to use any imports and library initialization). 
    Also you should add 2-3 state variables and 2-3 functions.
    Ensure that the contract code is valid, doesn't include any undeclared identifiers and can be successfully compiled by solidity compiler.

    Generate response in JSON format with no extra comments or explanations.
    Answer with only JSON text, without markdown formatting, without any formatting.

    Output format:
    {{
        "code": "Solidity code of the contract"
    }}
    """.strip()


solc = SolcSingleton()


def generate_contract(prompt: str) -> SmartContract | None:
    completion = client.chat.completions.create(
        model=GPT_MODEL,
        messages=[
            {"role": ROLES.SYSTEM, "content": prompt},
            {
                "role": ROLES.USER,
                "content": f"Generate new valid smart contract",
            },
        ],
        temperature=0.3,
    )

    return completion.choices[0].message.content


def try_prepare_contract(result) -> SmartContract | None:
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except:
            return None
    if not isinstance(result, dict):
        return None
    if "code" not in result:
        return None
    return SmartContract(code=result["code"])


def generate_task(requested_vulnerability: str | None = None) -> ValidatorTask:
    possible_vulnerabilities = [requested_vulnerability]
    completion = client.chat.completions.create(
        model=GPT_MODEL,
        messages=[
            {"role": ROLES.SYSTEM, "content": PROMPT_VALIDATOR},
        {
            "role": ROLES.USER,
            "content": f"Generate new vulnerable contract with one of "
            f"vulnerabilities: {', '.join(possible_vulnerabilities)}",
        },
        ],
        temperature=0.3,
    )

    return completion.choices[0].message.content


# /task
def get_task(requested_vulnerability: str | None = None):
    contract_code = generate_task(requested_vulnerability)

    return contract_code


# /hybrid_task
def get_hybrid_task(requested_vulnerability: str | None = None):
    tries = int(os.getenv("MAX_TRIES", "3"))
    is_valid, result = False, None
    if requested_vulnerability not in VULNERABILITIES_TO_GENERATE:
        requested_vulnerability = None

    while tries > 0:
        print(f"{requested_vulnerability.lower() if requested_vulnerability else None}")
        raw_vulnerability = get_vulnerability(
            requested_vulnerability.lower() if requested_vulnerability else None
        )
        print(f"Raw vulnerability code: {repr(raw_vulnerability.code)}")
        raw_vulnerability = Vulnerability(
            vulnerabilityClass=raw_vulnerability.name, code=raw_vulnerability.code
        )

        # tries -= 1
        # try:
        #     compile_contract_with_standart_input(
        #         create_contract(raw_vulnerability.code)
        #     )
        # except Exception as e:
        #     print(f"Vulnerability compilation error: {e}")
        #     continue

        result = generate_contract(
            get_hybrid_validator_prompt(raw_vulnerability.code)
        )
        print(f"Generated contract: {repr(result)}")

        # try:
        #     solc.compile(result.code)
        # except Exception as e:
        #     print(f"Compilation error: {e}")
        #     continue

        if result is not None:
            is_valid = True
            break
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid answer from LLM")

    try:
        task = create_task(result.code, raw_vulnerability)
        print(f"Task code: {repr(task.contract_code)}")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return task.contract_code


# /valid_contract
def get_valid_contract():
    return generate_contract(prompt=PROMPT_VALID_CONTRACT)

    # return ValidatorTask(
    #     contract_code=result.code,
    #     task_type=TaskType.VALID_CONTRACT,
    #     from_line=1,
    #     to_line=len(result.code.splitlines()) + 1,
    #     vulnerability_class="Valid contract",
    # )


import csv


def write_to_file(code, type, vulnerability_class, filename):
    with open(filename, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([code, vulnerability_class, type])


# class TaskType(StrEnum):
#     HYBRID = "hybrid_task"
#     LLM = "task"
#     RANDOM_TEXT = "random_task"
#     VALID_CONTRACT = "valid_contract"
if __name__ == "__main__":
    import os
    import concurrent.futures
    from enum import Enum
    folder_path = "data"
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    types = [
        "hybrid_task",
        # "task",
        # "random_task",
        # "valid_contract",
    ]
    number_samples = 100
    for _ in range(number_samples):
        for vul in VULNERABILITIES_TO_GENERATE:
            for type in types:
                code = get_hybrid_task(vul)
                write_to_file(code, type, vul, f"{folder_path}/{type}.csv")
                print(f"GENERATED: {vul} FOR {type}")
    # def process_sample(type, number_samples, folder_path):
    #     if type == TaskType.HYBRID:

    #         def task_fn(vulnerability):
    #             code = get_hybrid_task(vulnerability)
    #             write_to_file(code, type, vulnerability, f"{folder_path}/{type}.csv")
    #             print(f"GENERATED: {vulnerability} FOR {type}")

    #         with concurrent.futures.ThreadPoolExecutor() as executor:
    #             for _ in range(number_samples):
    #                 executor.map(task_fn, VULNERABILITIES_TO_GENERATE)

    #     elif type == TaskType.LLM:

    #         def task_fn(vulnerability):
    #             code = get_task(vulnerability)
    #             write_to_file(code, type, vulnerability, f"{folder_path}/{type}.csv")
    #             print(f"GENERATED: {vulnerability} FOR {type}")

    #         with concurrent.futures.ThreadPoolExecutor() as executor:
    #             for _ in range(number_samples):
    #                 executor.map(task_fn, VULNERABILITIES_TO_GENERATE)

    #     elif type == TaskType.RANDOM_TEXT:

    #         def task_fn(_):
    #             code = SolidityGenerator.generate_contract()
    #             write_to_file(code, type, "Invalid code", f"{folder_path}/{type}.csv")
    #             print(f"GENERATED: Invalid code FOR {type}")

    #         with concurrent.futures.ThreadPoolExecutor() as executor:
    #             executor.map(task_fn, range(number_samples))

    #     elif type == TaskType.VALID_CONTRACT:

    #         def task_fn(_):
    #             code = get_valid_contract()
    #             write_to_file(code, type, "Valid contract", f"{folder_path}/{type}.csv")
    #             print(f"GENERATED: Valid contract FOR {type}")

    #         with concurrent.futures.ThreadPoolExecutor() as executor:
    #             executor.map(task_fn, range(number_samples))


    # # Main multi-threaded dispatcher per task type
    # with concurrent.futures.ThreadPoolExecutor() as type_executor:
    #     futures = [
    #         type_executor.submit(process_sample, type, number_samples, folder_path)
    #         for type in types
    #     ]
    #     concurrent.futures.wait(futures)
