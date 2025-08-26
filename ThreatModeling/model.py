from langchain_community.llms import Ollama
from langchain_community.llms import DeepInfra
import yaml


def get_ollama_model():
    """
    Get the Ollama model with the parameters from the parameters.yaml file.
    """
    with open("threatmodeling/parameters.yaml", "r") as f:
        parameters = yaml.safe_load(f)
    return Ollama(
        model=parameters["ollama"]["model"],
        temperature=parameters["ollama"]["temperature"],
    )


def get_deepinfra_model():
    """
    Get the DeepInfra model with the parameters from the parameters.yaml file.
    """
    with open("threatmodeling/parameters.yaml", "r") as f:
        parameters = yaml.safe_load(f)
    llm = DeepInfra(model_id=parameters["deepinfra"]["model"])
    llm.model_kwargs = {
        "temperature": parameters["deepinfra"]["temperature"],
        "max_new_tokens": parameters["deepinfra"]["max_new_tokens"],
    }
    return llm
