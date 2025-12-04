from engine import engine_system_prompt


from agents import Agent, Runner
from agents.tracing.span_data import HandoffSpanData
from agents.tracing import trace
from agents.model_settings import ModelSettings
from engine.engine_system_prompt import Engine_system_prompt


engine_system_promptt = Engine_system_prompt()



class Engine:
    """
    Triage agent that handles triage tasks.
    """
    
    def __init__(self):
        
        self.engine = Agent(
            name="engine",
            model="o3",
            instructions=engine_system_promptt.get_system_prompt()
        )


