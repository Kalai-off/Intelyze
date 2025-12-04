class Engine_system_prompt:
    def __init__(self):


        self.engine_system_prompt = """You are a helpful assistant capable of processing csv and excel files through a code interpreter."""
    def get_system_prompt(self) -> str:
        """
        Returns the system prompt for the triaging agent.
        """
        return self.engine_system_prompt
