"""
Entry point for running the consumer as a module: python -m consumer
"""
from consumer.consumer import run
import asyncio

if __name__ == "__main__":
    asyncio.run(run())

