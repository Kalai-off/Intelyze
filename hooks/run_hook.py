import asyncio
import random
from typing import Any
import os
import csv
from datetime import datetime
import json  # Ensure JSON handling is imported
import threading

from pydantic import BaseModel

from agents import Agent, RunContextWrapper, RunHooks, Runner, Tool, Usage, function_tool

class RunHook(RunHooks):
    def __init__(self):
        self.event_counter = 0
        self.log_file = "app_log.csv"
        # Initialize the CSV file with headers if it doesn't exist
        if not os.path.exists(self.log_file):
            with open(self.log_file, mode="w", encoding="utf-8", newline="") as file:  # Use utf-8 encoding
                writer = csv.writer(file)
                writer.writerow(["Timestamp", "Event Type", "Tool/Agent Name", "Input", "Output"])

    def _usage_to_str(self, usage: Usage) -> str:
        return f"{usage.requests} requests, {usage.input_tokens} input tokens, {usage.output_tokens} output tokens, {usage.total_tokens} total tokens"

    def _log_event(self, event_type: str, name: str, input_data: str, output_data: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, mode="a", encoding="utf-8", newline="") as file:  # Use utf-8 encoding
            writer = csv.writer(file)
            writer.writerow([timestamp, event_type, name, input_data, output_data])

        # Trigger background sync of the CSV log (best-effort)
        try:
            def _bg_sync(logpath):
                try:
                    from sync.remote_sync import sync_path
                    # Upload log file directly to bucket root (remote_subpath = filename only)
                    sync_path(logpath, remote_subpath="app_log.csv")
                except Exception as _e:
                    print("run_hook: background sync failed:", _e)
            t = threading.Thread(target=_bg_sync, args=(self.log_file,), daemon=True)
            t.start()
        except Exception:
            pass

    async def on_agent_start(self, context: RunContextWrapper, agent: Agent) -> None:
        self.event_counter += 1
        input_data = "N/A"  # No longer using conversation history
        self._log_event("Agent Start", agent.name, input_data, "N/A")
        print(
            f"### {self.event_counter}: Agent {agent.name} started. Usage: {self._usage_to_str(context.usage)}"
        )

    async def on_agent_end(self, context: RunContextWrapper, agent: Agent, output: Any) -> None:
        self.event_counter += 1
        input_data = "N/A"  # No longer using conversation history
        self._log_event("Agent End", agent.name, input_data, str(output))
        print(
            f"### {self.event_counter}: Agent {agent.name} ended with output {output}. Usage: {self._usage_to_str(context.usage)}"
        )

    async def on_tool_start(self, context: RunContextWrapper, agent: Agent, tool: Tool) -> None:
        self.event_counter += 1
        input_data = f"Tool Name: {tool.name}"
        self._log_event("Tool Start", tool.name, input_data, "N/A")
        print(
            f"### {self.event_counter}: Tool {tool.name} started. Usage: {self._usage_to_str(context.usage)}"
        )

    async def on_tool_end(
        self, context: RunContextWrapper, agent: Agent, tool: Tool, result: str
    ) -> None:
        self.event_counter += 1
        input_data = f"Tool Name: {tool.name}"
        self._log_event("Tool End", tool.name, input_data, result)
        print(
            f"### {self.event_counter}: Tool {tool.name} ended with result {result}. Usage: {self._usage_to_str(context.usage)}"
        )


    async def on_handoff(
        self, context: RunContextWrapper, from_agent: Agent, to_agent: Agent
    ) -> None:
        self.event_counter += 1
        input_data = f"From Agent: {from_agent.name}, To Agent: {to_agent.name}"
        self._log_event("Handoff", f"{from_agent.name} -> {to_agent.name}", input_data, "N/A")
        print(
            f"### {self.event_counter}: Handoff from {from_agent.name} to {to_agent.name}. Usage: {self._usage_to_str(context.usage)}"
        )